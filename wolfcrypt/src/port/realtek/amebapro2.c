/* amebapro2.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_REALTEK_HUK

#include <wolfssl/wolfcrypt/port/realtek/amebapro2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Vendor HAL surface: the real SDK headers on target, the host-test shim under
 * --enable-amebapro2 (see amebapro2_shim.h). The on-target include path is
 * supplied by the application / board CMake (see this port's README). */
#ifdef WOLFSSL_AMEBAPRO2_HOST_TEST
    #include "amebapro2_shim.h"
#else
    #include "hal_crypto.h"
    #include "hal_hkdf.h"
    #ifdef HAVE_ECC
        #include "hal_ecdsa.h"
    #endif
#endif

#ifdef WOLF_CRYPTO_CB

/* The HUK-derived working key is always a 256-bit key. */
#define WC_AMEBAPRO2_KEYLEN 32

/* The HAL crypto engine DMAs its key/iv/aad/tag buffers on 32-byte (cache line)
 * boundaries; unaligned caller buffers are bounced through aligned temporaries
 * so callers need not align. */
#define WC_AMEBAPRO2_IS_ALIGNED32(p) ((((wc_ptr_t)(p)) & 31u) == 0)

static int AmebaPro2Huk_Init(void* ctx)
{
    (void)ctx;
    /* One-time crypto engine bring-up. Idempotent on the HAL side. */
    if (hal_crypto_engine_init() != 0) {
        return WC_HW_E;
    }
    return 0;
}

/* Run the HUK key-ladder on the per-operation seed (the 32-byte HKDF input the
 * Aes carries in devKey): HUK (secure key slot) -> HKDF-Extract(secure) -> PRK
 * slot -> HKDF-Expand(secure) -> device-bound working key in the derived slot.
 * The working key never enters software; on return it resides in
 * WC_AMEBAPRO2_DERIVED_WB_IDX, ready for an AES *_sk_init that references that
 * slot. The seed is passed by argument (not held in a global), so concurrent
 * Aes objects never race; the caller holds the crypto mutex across derive + op.
 *
 * The HUK is the built-in secure key at slot WC_AMEBAPRO2_HUK_SK_IDX (HUK1); the
 * engine reads it internally. We deliberately do NOT lock the derived slot: each
 * operation re-derives the working key into it, and a locked key-storage slot
 * silently rejects that re-derivation (it would keep a stale key, so a different
 * seed would yield the wrong result). The slot is overwritten on the next
 * derive; nothing reads it back into software. */
static int AmebaPro2Huk_DeriveSlotKey(const byte* seed)
{
    XALIGNED(32) byte seedA[WC_AMEBAPRO2_KEYLEN];

    if (seed == NULL) {
        return BAD_FUNC_ARG;
    }
    /* HKDF reads the seed via DMA -- pass it a 32-byte-aligned copy. */
    XMEMCPY(seedA, seed, WC_AMEBAPRO2_KEYLEN);

    /* Init the secure HKDF HMAC-SHA256 engine (sets isHWCrypto_Init); required
     * before any *_secure_all call or extract returns HW_NOT_INIT. */
    if (hal_hkdf_hmac_sha256_secure_init((u8)WC_AMEBAPRO2_HKDF_CRYPTO_SEL)
            != HAL_OK) {
        return WC_HW_E;
    }
    /* HKDF-Extract: PRK = HMAC(HUK, seed), into the PRK slot. */
    if (hal_hkdf_extract_secure_all((u8)WC_AMEBAPRO2_HUK_SK_IDX,
            (u8)WC_AMEBAPRO2_HKDF_PRK_IDX, seedA) != HAL_OK) {
        return WC_HW_E;
    }
    /* HKDF-Expand: OKM = working key, into the derived working-key slot. */
    if (hal_hkdf_expand_secure_all((u8)WC_AMEBAPRO2_HKDF_PRK_IDX,
            (u8)WC_AMEBAPRO2_DERIVED_WB_IDX, seedA) != HAL_OK) {
        return WC_HW_E;
    }
    return 0;
}

#ifndef NO_AES

#ifdef HAVE_AESGCM
/* Full AES-GCM (encrypt or decrypt-verify) under a HUK-derived slot key.
 * The HAL GCM path assumes a 96-bit (12-byte) IV (standard J0). For a HUK key
 * we must not fall back to software GCM (the software path would key off the
 * seed, not the device-bound key), so an unsupported IV length is a hard error,
 * not CRYPTOCB_UNAVAILABLE. */
static int AmebaPro2Huk_Gcm(int enc, const byte* seed, const byte* in,
    word32 sz, byte* out, const byte* iv, word32 ivSz, const byte* aad,
    word32 aadSz, byte* tag, word32 tagSz)
{
    int   ret;
    /* 16-byte aligned IV block: the HAL reads a full block, so the 4 bytes past
     * the 12-byte nonce must be zero and stable across calls. */
    XALIGNED(32) byte ivA[WC_AES_BLOCK_SIZE]   = { 0 };
    XALIGNED(32) byte hwTag[WC_AES_BLOCK_SIZE] = { 0 };
    const byte* inA  = in;       /* aligned views; bounced below if needed */
    const byte* aadA = aad;
    byte*       outA = out;
    byte* inBounce  = NULL;
    byte* outBounce = NULL;
    byte* aadBounce = NULL;

    if (ivSz != GCM_NONCE_MID_SZ) {
        return NOT_COMPILED_IN; /* only 12-byte GCM IV supported by the HAL */
    }
    if (tag == NULL || tagSz == 0 || tagSz > WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    /* Bounce any unaligned DMA buffer through a 32-byte-aligned temporary. iv
     * and tag are small and always staged on aligned stack buffers; in/out/aad
     * may be large, so are only copied when actually unaligned. */
    XMEMCPY(ivA, iv, GCM_NONCE_MID_SZ);
    if (aadSz > 0 && !WC_AMEBAPRO2_IS_ALIGNED32(aad)) {
        aadBounce = (byte*)XMALLOC(aadSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (aadBounce == NULL) {
            return MEMORY_E;
        }
        XMEMCPY(aadBounce, aad, aadSz);
        aadA = aadBounce;
    }
    if (sz > 0 && !WC_AMEBAPRO2_IS_ALIGNED32(in)) {
        inBounce = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (inBounce == NULL) {
            ret = MEMORY_E;
            goto cleanup;
        }
        XMEMCPY(inBounce, in, sz);
        inA = inBounce;
    }
    if (sz > 0 && !WC_AMEBAPRO2_IS_ALIGNED32(out)) {
        outBounce = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBounce == NULL) {
            ret = MEMORY_E;
            goto cleanup;
        }
        outA = outBounce;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto cleanup;
    }
    ret = AmebaPro2Huk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto unlock;
    }
    if (hal_crypto_aes_gcm_sk_init((byte)WC_AMEBAPRO2_DERIVED_WB_IDX,
            WC_AMEBAPRO2_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto unlock;
    }
    XMEMSET(hwTag, 0, sizeof(hwTag));
    if (enc) {
        if (hal_crypto_aes_gcm_encrypt(inA, sz, ivA, aadA, aadSz, outA, hwTag)
                != 0) {
            ret = WC_HW_E;
            goto unlock;
        }
        XMEMCPY(tag, hwTag, tagSz);
        ret = 0;
    }
    else {
        if (hal_crypto_aes_gcm_decrypt(inA, sz, ivA, aadA, aadSz, outA, hwTag)
                != 0) {
            ret = WC_HW_E;
            goto unlock;
        }
        if (ConstantCompare(hwTag, tag, (int)tagSz) != 0) {
            if (outA != NULL && sz != 0) {
                ForceZero(outA, sz);
            }
            ret = AES_GCM_AUTH_E;
        }
        else {
            ret = 0;
        }
    }
    if (ret == 0 && outBounce != NULL) {
        XMEMCPY(out, outBounce, sz);
    }

unlock:
    ForceZero(hwTag, sizeof(hwTag));
    wolfSSL_CryptHwMutexUnLock();
cleanup:
    if (inBounce != NULL) {
        XFREE(inBounce, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (outBounce != NULL) {
        ForceZero(outBounce, sz);
        XFREE(outBounce, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (aadBounce != NULL) {
        XFREE(aadBounce, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}
#endif /* HAVE_AESGCM */

/* AES-ECB under a HUK-derived slot key. sz must be a multiple of the block. */
static int AmebaPro2Huk_Ecb(int enc, const byte* seed, const byte* in,
    word32 sz, byte* out)
{
    int ret;

    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ret = AmebaPro2Huk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto out;
    }
    if (hal_crypto_aes_ecb_sk_init((byte)WC_AMEBAPRO2_DERIVED_WB_IDX,
            WC_AMEBAPRO2_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto out;
    }
    if (enc) {
        ret = hal_crypto_aes_ecb_encrypt(in, sz, NULL, 0, out);
    }
    else {
        ret = hal_crypto_aes_ecb_decrypt(in, sz, NULL, 0, out);
    }
    if (ret != 0) {
        ret = WC_HW_E;
    }

out:
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

#ifdef HAVE_AES_CBC
/* AES-CBC under a HUK-derived slot key. The HAL has no CBC secure-key variant
 * (only ECB/GCM expose *_sk_init), so chain in software over single-block
 * ECB-sk operations -- the key still never leaves hardware. iv is the 16-byte
 * chaining block (aes->reg); the dispatcher advances it for the next call. */
static int AmebaPro2Huk_Cbc(int enc, const byte* seed, const byte* in,
    word32 sz, byte* out, const byte* iv)
{
    int    ret;
    word32 off;
    XALIGNED(32) byte prev[WC_AES_BLOCK_SIZE];
    XALIGNED(32) byte blk[WC_AES_BLOCK_SIZE];

    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0 || iv == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ret = AmebaPro2Huk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto out;
    }
    if (hal_crypto_aes_ecb_sk_init((byte)WC_AMEBAPRO2_DERIVED_WB_IDX,
            WC_AMEBAPRO2_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto out;
    }

    XMEMCPY(prev, iv, WC_AES_BLOCK_SIZE);
    for (off = 0; off < sz; off += WC_AES_BLOCK_SIZE) {
        if (enc) {
            /* C_i = ECB_enc(P_i XOR C_{i-1}) */
            xorbufout(blk, in + off, prev, WC_AES_BLOCK_SIZE);
            ret = hal_crypto_aes_ecb_encrypt(blk, WC_AES_BLOCK_SIZE, NULL, 0,
                                             out + off);
            if (ret != 0) {
                ret = WC_HW_E;
                goto out;
            }
            XMEMCPY(prev, out + off, WC_AES_BLOCK_SIZE);
        }
        else {
            /* P_i = ECB_dec(C_i) XOR C_{i-1} */
            ret = hal_crypto_aes_ecb_decrypt(in + off, WC_AES_BLOCK_SIZE, NULL,
                                             0, blk);
            if (ret != 0) {
                ret = WC_HW_E;
                goto out;
            }
            xorbufout(out + off, blk, prev, WC_AES_BLOCK_SIZE);
            XMEMCPY(prev, in + off, WC_AES_BLOCK_SIZE);
        }
    }
    ret = 0;

out:
    ForceZero(prev, sizeof(prev));
    ForceZero(blk, sizeof(blk));
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
/* Increment a 16-byte big-endian (network order) counter in place. */
static void AmebaPro2Huk_IncCtr(byte* ctr)
{
    int i;
    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++ctr[i] != 0) {
            break;
        }
    }
}

/* AES-CTR under a HUK-derived slot key. The HAL has no CTR secure-key variant,
 * so generate the keystream by ECB-sk encrypting the counter and XOR it with the
 * data -- the key never leaves hardware. Maintains the wolfCrypt CTR state:
 * aes->reg (counter), aes->tmp (current keystream block) and aes->left (unused
 * keystream bytes at the tail of aes->tmp) so partial blocks continue across
 * calls exactly as the software path does. The counter is staged on an aligned
 * stack buffer, so caller in/out alignment does not matter (only XORed here). */
static int AmebaPro2Huk_Ctr(Aes* aes, const byte* seed, const byte* in,
    word32 sz, byte* out)
{
    int    ret;
    word32 processed;
    XALIGNED(32) byte ctr[WC_AES_BLOCK_SIZE] = { 0 };
    XALIGNED(32) byte ks[WC_AES_BLOCK_SIZE]  = { 0 };

    if (aes == NULL || (sz != 0 && (in == NULL || out == NULL))) {
        return BAD_FUNC_ARG;
    }

    /* Consume any keystream left over from a previous call (no HW needed). */
    processed = (aes->left < sz) ? aes->left : sz;
    if (processed > 0) {
        xorbufout(out, in,
                  (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left, processed);
        out += processed;
        in  += processed;
        aes->left -= processed;
        sz  -= processed;
    }
    if (sz == 0) {
        return 0;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ret = AmebaPro2Huk_DeriveSlotKey(seed);
    if (ret != 0) {
        goto out;
    }
    if (hal_crypto_aes_ecb_sk_init((byte)WC_AMEBAPRO2_DERIVED_WB_IDX,
            WC_AMEBAPRO2_KEYLEN) != 0) {
        ret = WC_HW_E;
        goto out;
    }

    XMEMCPY(ctr, aes->reg, WC_AES_BLOCK_SIZE);
    while (sz >= WC_AES_BLOCK_SIZE) {
        ret = hal_crypto_aes_ecb_encrypt(ctr, WC_AES_BLOCK_SIZE, NULL, 0, ks);
        if (ret != 0) {
            ret = WC_HW_E;
            goto out;
        }
        xorbufout(out, in, ks, WC_AES_BLOCK_SIZE);
        AmebaPro2Huk_IncCtr(ctr);
        out += WC_AES_BLOCK_SIZE;
        in  += WC_AES_BLOCK_SIZE;
        sz  -= WC_AES_BLOCK_SIZE;
    }
    if (sz > 0) {
        /* Final partial block: keep the unused keystream for the next call. */
        ret = hal_crypto_aes_ecb_encrypt(ctr, WC_AES_BLOCK_SIZE, NULL, 0, ks);
        if (ret != 0) {
            ret = WC_HW_E;
            goto out;
        }
        XMEMCPY(aes->tmp, ks, WC_AES_BLOCK_SIZE);
        xorbufout(out, in, ks, sz);
        AmebaPro2Huk_IncCtr(ctr);
        aes->left = WC_AES_BLOCK_SIZE - sz;
    }
    XMEMCPY(aes->reg, ctr, WC_AES_BLOCK_SIZE);
    ret = 0;

out:
    ForceZero(ks, sizeof(ks));
    ForceZero(ctr, sizeof(ctr));
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

/* The 256-bit seed an Aes carries in devKey (set via the normal key API) is the
 * per-operation HKDF input. Point *seed at it, or return CRYPTOCB_UNAVAILABLE if
 * this is not a 256-bit seed key (so non-HUK keys fall back to software). */
static int AmebaPro2Huk_AesSeed(Aes* aes, const byte** seed)
{
    if (aes == NULL || aes->keylen != WC_AMEBAPRO2_KEYLEN) {
        return CRYPTOCB_UNAVAILABLE;
    }
    *seed = (const byte*)aes->devKey;
    return 0;
}

/* Route a cipher (AES ECB/CBC/CTR, AES-GCM) request to the HUK backend. */
static int AmebaPro2Huk_Cipher(struct wc_CryptoInfo* info)
{
    int ret;
    const byte* seed = NULL;

    switch (info->cipher.type) {
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
    case WC_CIPHER_AES_ECB:
        ret = AmebaPro2Huk_AesSeed(info->cipher.aesecb.aes, &seed);
        if (ret != 0) {
            return ret;
        }
        return AmebaPro2Huk_Ecb(info->cipher.enc, seed, info->cipher.aesecb.in,
                                info->cipher.aesecb.sz, info->cipher.aesecb.out);
#endif
#if defined(HAVE_AES_CBC)
    case WC_CIPHER_AES_CBC:
        ret = AmebaPro2Huk_AesSeed(info->cipher.aescbc.aes, &seed);
        if (ret != 0) {
            return ret;
        }
        ret = AmebaPro2Huk_Cbc(info->cipher.enc, seed, info->cipher.aescbc.in,
                               info->cipher.aescbc.sz, info->cipher.aescbc.out,
                               (const byte*)info->cipher.aescbc.aes->reg);
        if (ret == 0) {
            /* Advance the chaining IV (aes->reg) for the next CBC call. */
            if (info->cipher.enc) {
                XMEMCPY(info->cipher.aescbc.aes->reg,
                        info->cipher.aescbc.out + info->cipher.aescbc.sz
                            - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
            }
            else {
                XMEMCPY(info->cipher.aescbc.aes->reg,
                        info->cipher.aescbc.in + info->cipher.aescbc.sz
                            - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
            }
        }
        return ret;
#endif
#ifdef WOLFSSL_AES_COUNTER
    case WC_CIPHER_AES_CTR:
        ret = AmebaPro2Huk_AesSeed(info->cipher.aesctr.aes, &seed);
        if (ret != 0) {
            return ret;
        }
        return AmebaPro2Huk_Ctr(info->cipher.aesctr.aes, seed,
                                info->cipher.aesctr.in, info->cipher.aesctr.sz,
                                info->cipher.aesctr.out);
#endif
#ifdef HAVE_AESGCM
    case WC_CIPHER_AES_GCM:
        if (info->cipher.enc) {
            ret = AmebaPro2Huk_AesSeed(info->cipher.aesgcm_enc.aes, &seed);
            if (ret != 0) {
                return ret;
            }
            return AmebaPro2Huk_Gcm(1, seed,
                                    info->cipher.aesgcm_enc.in,
                                    info->cipher.aesgcm_enc.sz,
                                    info->cipher.aesgcm_enc.out,
                                    info->cipher.aesgcm_enc.iv,
                                    info->cipher.aesgcm_enc.ivSz,
                                    info->cipher.aesgcm_enc.authIn,
                                    info->cipher.aesgcm_enc.authInSz,
                                    info->cipher.aesgcm_enc.authTag,
                                    info->cipher.aesgcm_enc.authTagSz);
        }
        else {
            ret = AmebaPro2Huk_AesSeed(info->cipher.aesgcm_dec.aes, &seed);
            if (ret != 0) {
                return ret;
            }
            return AmebaPro2Huk_Gcm(0, seed,
                                    info->cipher.aesgcm_dec.in,
                                    info->cipher.aesgcm_dec.sz,
                                    info->cipher.aesgcm_dec.out,
                                    info->cipher.aesgcm_dec.iv,
                                    info->cipher.aesgcm_dec.ivSz,
                                    info->cipher.aesgcm_dec.authIn,
                                    info->cipher.aesgcm_dec.authInSz,
                                    (byte*)info->cipher.aesgcm_dec.authTag,
                                    info->cipher.aesgcm_dec.authTagSz);
        }
#endif
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}
#endif /* !NO_AES */

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
/* Route an ECDSA sign request to the HUK / ECDSA backend.
 *
 * Stage 3 (follow-on): two private-key models are planned --
 *   (a) wrapped-scalar: reuse key->dhuk_wrapped_priv / dhuk_seed, derive a slot
 *       key, AES-ECB-decrypt the wrapped scalar into a short-lived buffer, sign
 *       via hal_ecdsa_signature, ForceZero, then StoreECC_DSA_Sig.
 *   (b) OTP-resident: hal_ecdsa_select_prk + hal_otp_ecdsa_key_get so the scalar
 *       never materializes in software.
 * Until implemented, return CRYPTOCB_UNAVAILABLE is unsafe for a HUK key (it
 * would fall back to a software sign keyed off nothing usable); the device
 * simply does not advertise ECDSA yet, so this returns NOT_COMPILED_IN. */
static int AmebaPro2Huk_PkSign(struct wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccsign.key;

    if (key == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (key->dhuk_seed_sz != WC_AMEBAPRO2_KEYLEN) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* TODO(stage3): implement HUK-bound ECDSA sign. */
    return NOT_COMPILED_IN;
}
#endif /* HAVE_ECC && HAVE_ECC_SIGN */

/* The crypto-callback device entry point (registered by
 * wc_AmebaPro2_HukRegister). Returns CRYPTOCB_UNAVAILABLE for anything it does
 * not handle so the caller falls back to software. */
static int AmebaPro2_CryptoDevCb(int devId, struct wc_CryptoInfo* info,
    void* ctx)
{
    (void)devId;
    (void)ctx;
    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->algo_type) {
#ifndef NO_AES
        case WC_ALGO_TYPE_CIPHER:
            return AmebaPro2Huk_Cipher(info);
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
        case WC_ALGO_TYPE_PK:
            if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
                return AmebaPro2Huk_PkSign(info);
            }
            return CRYPTOCB_UNAVAILABLE;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

/* Register the AmebaPro2 HUK device at devId (e.g. WC_HUK_DEVID). After this,
 * objects whose devId is set to it at init route transparently to the HUK
 * crypto engine. */
int wc_AmebaPro2_HukRegister(int devId)
{
    int ret = AmebaPro2Huk_Init(NULL);
    if (ret != 0) {
        return ret;
    }
    return wc_CryptoCb_RegisterDevice(devId, AmebaPro2_CryptoDevCb, NULL);
}

void wc_AmebaPro2_HukUnRegister(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
    /* No port-global secret to scrub: each op derives from the Aes' own devKey
     * seed under the crypto mutex; the working key lives only in the HW slot. */
}

#endif /* WOLF_CRYPTO_CB */

#endif /* WOLFSSL_REALTEK_HUK */
