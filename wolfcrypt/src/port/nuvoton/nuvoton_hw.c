/* nuvoton_hw.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* The secure-world half of the Nuvoton NuMicro M2354 port: the only file in
 * the port that includes a BSP header. It is compiled when wolfCrypt itself
 * runs in the secure world (WOLFSSL_NUVOTON_SECURE), and on the secure side of
 * a TrustZone split, where the veneers in IDE/Nuvoton/M2354/secure/ forward to
 * it. Under WOLFSSL_NUVOTON_NSC nothing here is built and those veneers
 * satisfy the wc_nuvoton_hw_* symbols instead. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_SECURE)

/* BSP StdDriver. The application puts M2354BSP/Library/StdDriver/inc,
 * Library/Device/Nuvoton/M2354/Include and Library/CMSIS/Include on the
 * include path.
 *
 * This has to come before any wolfSSL header other than settings.h. M2354.h
 * defines TRUE and FALSE unconditionally as (1L) and (0L), while types.h
 * defines them as 1 and 0 behind an #ifndef. Whichever is second wins quietly
 * unless it is the BSP, which then redefines them and fails a -Werror build. */
#include "NuMicro.h"

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#ifdef WOLFSSL_NUVOTON_CIPHER
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* How many times wc_nuvoton_hw_init() has been called without a matching
 * wc_nuvoton_hw_cleanup(). The hardware comes up on the first and goes down on
 * the last, so several independent devices or a re-registration do not fight
 * over it. Guarded by the wolfCrypt hardware mutex. */
static int nuvotonRefCount = 0;

/* CRPT DMA reads and writes only word-aligned addresses in the 0x2xxxxxxx SRAM
 * region. Nuvoton states the requirement in the BSP's own mbedTLS layer
 * (Library/CryptoAccelerator/aes_alt.c): "(1) Word-aligned (2) Located in
 * 0x2xxxxxxx region." */
#define NUVOTON_DMA_REGION_MASK  0xF0000000u
#define NUVOTON_DMA_REGION_SRAM  0x20000000u

static int nuvoton_dma_ok(const void* p, word32 sz)
{
    uint32_t addr = (uint32_t)(uintptr_t)p;

    if (sz == 0) {
        return 1;
    }
    if ((addr & 0x3u) != 0) {
        return 0;
    }
    if ((addr & NUVOTON_DMA_REGION_MASK) != NUVOTON_DMA_REGION_SRAM) {
        return 0;
    }

    return 1;
}

#ifdef WOLFSSL_NUVOTON_KS

/* Map the port's Key Store selector onto the BSP KS_MEM_Type. The two enums
 * happen to agree, but the mapping is written out so a BSP renumbering shows
 * up here as a compile problem rather than as keys landing in the wrong
 * store. */
static int nuvoton_ks_mem(int keyMem, KS_MEM_Type* mem)
{
    switch (keyMem) {
        case WC_NUVOTON_KS_SRAM:
            *mem = KS_SRAM;
            break;
        case WC_NUVOTON_KS_FLASH:
            *mem = KS_FLASH;
            break;
        case WC_NUVOTON_KS_OTP:
            *mem = KS_OTP;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

#endif /* WOLFSSL_NUVOTON_KS */

int wc_nuvoton_hw_init(void)
{
    int ret = 0;

    ret = wolfSSL_CryptHwMutexInit();
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (nuvotonRefCount == 0) {
        SYS_UnlockReg();

        /* CRPT and the Key Store share the AHB clock domain; the TRNG has its
         * own on APB1 and RNG_Open() ungates it. */
        CLK_EnableModuleClock(CRPT_MODULE);
        CLK_EnableModuleClock(KS_MODULE);
        SYS_ResetModule(CRPT_RST);

        if (KS_Open() != 0) {
            WOLFSSL_MSG("Nuvoton: KS_Open failed");
            ret = WC_HW_E;
        }

        /* Brings the TRNG up and points the CRPT PRNG seed generator at it. */
        if (ret == 0 && RNG_Open() != 0) {
            WOLFSSL_MSG("Nuvoton: RNG_Open failed");
            ret = WC_HW_E;
        }

        SYS_LockReg();

        if (ret != 0) {
            CLK_DisableModuleClock(KS_MODULE);
            CLK_DisableModuleClock(CRPT_MODULE);
        }
    }

    if (ret == 0) {
        nuvotonRefCount++;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void wc_nuvoton_hw_cleanup(void)
{
    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    if (nuvotonRefCount > 0) {
        nuvotonRefCount--;

        if (nuvotonRefCount == 0) {
            SYS_UnlockReg();
            SYS_ResetModule(CRPT_RST);
            CLK_DisableModuleClock(KS_MODULE);
            CLK_DisableModuleClock(CRPT_MODULE);
            SYS_LockReg();
        }
    }

    wolfSSL_CryptHwMutexUnLock();
}

#ifdef WOLFSSL_NUVOTON_TRNG

int wc_nuvoton_hw_trng(byte* out, word32 sz)
{
    int      ret = 0;
    int      got;
    word32   chunk;
    /* RNG_Random() fills whole words and hands back at most eight of them per
     * call, so a partial word at the tail is taken from a staging word rather
     * than written past the caller's buffer. */
    uint32_t buf[8];

    if (out == NULL || sz == 0) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    while (sz > 0) {
        chunk = sz;
        if (chunk > sizeof(buf)) {
            chunk = (word32)sizeof(buf);
        }

        /* RNG_Random() returns the number of words it produced, and zero when
         * it timed out waiting on the engine. It is not a signed error. */
        got = RNG_Random(buf, (int32_t)((chunk + 3) / 4));
        if (got <= 0) {
            WOLFSSL_MSG("Nuvoton: RNG_Random failed");
            ret = RNG_FAILURE_E;
            break;
        }

        if (chunk > (word32)got * 4) {
            chunk = (word32)got * 4;
        }

        XMEMCPY(out, buf, chunk);
        out += chunk;
        sz  -= chunk;
    }

    ForceZero(buf, sizeof(buf));

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_TRNG */


#ifdef WOLFSSL_NUVOTON_HASH

/* Map the port's hash selector onto the BSP SHA_MODE_* value. */
static int nuvoton_sha_mode(int shaMode, uint32_t* opMode)
{
    switch (shaMode) {
        case WC_NUVOTON_SHA_1:
            *opMode = SHA_MODE_SHA1;
            break;
        case WC_NUVOTON_SHA_224:
            *opMode = SHA_MODE_SHA224;
            break;
        case WC_NUVOTON_SHA_256:
            *opMode = SHA_MODE_SHA256;
            break;
        case WC_NUVOTON_SHA_384:
            *opMode = SHA_MODE_SHA384;
            break;
        case WC_NUVOTON_SHA_512:
            *opMode = SHA_MODE_SHA512;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* Map the port's cascade position onto the BSP CRYPTO_DMA_* value. The BSP
 * packs DMAEN, DMACSCAD and DMALAST into the one field SHA_Start() shifts into
 * HMAC_CTL, so every value here has DMAEN set. */
static int nuvoton_dma_mode(int dmaMode, uint32_t* bspMode)
{
    switch (dmaMode) {
        case WC_NUVOTON_DMA_ONE_SHOT:
            *bspMode = CRYPTO_DMA_ONE_SHOT;
            break;
        case WC_NUVOTON_DMA_FIRST:
            *bspMode = CRYPTO_DMA_FIRST;
            break;
        case WC_NUVOTON_DMA_CONTINUE:
            *bspMode = CRYPTO_DMA_CONTINUE;
            break;
        case WC_NUVOTON_DMA_LAST:
            *bspMode = CRYPTO_DMA_LAST;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_sha(wc_NuvotonShaReq* req)
{
    int      ret;
    uint32_t opMode = 0;
    uint32_t bspMode = 0;
    word32   timeout;
    /* SHA_Read() writes as many words as the current op mode produces, which
     * is sixteen for SHA-512 and fewer for the rest. */
    uint32_t dgst[16];

    if (req == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->digest == NULL || req->digestSz == 0 ||
        req->digestSz > sizeof(dgst)) {
        return BAD_FUNC_ARG;
    }
    if (req->in == NULL && req->inSz > 0) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_sha_mode(req->shaMode, &opMode);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_dma_mode(req->dmaMode, &bspMode);
    if (ret != 0) {
        return ret;
    }

    /* The engine has no path that produces the digest of an empty message: the
     * result register is only written by a DMA round, and a zero-length round
     * does not start one. Report it so the caller falls back to software. */
    if (req->inSz == 0) {
        return BAD_LENGTH_E;
    }

    /* The message is read by DMA, so it has to satisfy the engine's addressing
     * rules. Report it rather than staging a whole message through the bounce
     * buffer, which would need a cascade and therefore exclusive use of the
     * engine across calls. */
    if (!nuvoton_dma_ok(req->in, req->inSz)) {
        return BAD_ALIGN_E;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    SHA_Open(CRPT, opMode, SHA_IN_OUT_SWAP, 0);
    SHA_SetDMATransfer(CRPT, (uint32_t)(uintptr_t)req->in, req->inSz);

    /* Clear the completion flag from whatever ran last, or the wait below
     * returns immediately. */
    CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;

    SHA_Start(CRPT, bspMode);

    /* Both conditions matter: the flag says a DMA round finished, and BUSY
     * says the engine has finished with it. The BSP checks both. */
    timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
    while (((CRPT->INTSTS & CRPT_INTSTS_HMACIF_Msk) == 0) ||
           ((CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk) != 0)) {
        if (timeout-- == 0) {
            WOLFSSL_MSG("Nuvoton: SHA timeout");
            wolfSSL_CryptHwMutexUnLock();
            return WC_TIMEOUT_E;
        }
    }

    if ((CRPT->HMAC_STS & CRPT_HMAC_STS_DMAERR_Msk) != 0) {
        WOLFSSL_MSG("Nuvoton: SHA DMA error");
        CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;
        wolfSSL_CryptHwMutexUnLock();
        return WC_HW_E;
    }

    CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;

    SHA_Read(CRPT, dgst);
    XMEMCPY(req->digest, dgst, req->digestSz);

    ForceZero(dgst, sizeof(dgst));

    wolfSSL_CryptHwMutexUnLock();

    return 0;
}

#endif /* WOLFSSL_NUVOTON_HASH */


#ifdef WOLFSSL_NUVOTON_CIPHER

/* The engine reads and writes the key, the IV and the feedback registers as
 * words holding the wire bytes in memory order, with KINSWAP and the data
 * INSWAP/OUTSWAP bits doing the endianness. Same convention as the BSP's own
 * mbedTLS layer, so these two helpers are just an explicit spelling of the
 * byte copy it does. */
static uint32_t nuvoton_get32(const byte* p)
{
    return ((uint32_t)p[0])        | (((uint32_t)p[1]) <<  8) |
           (((uint32_t)p[2]) << 16) | (((uint32_t)p[3]) << 24);
}

static void nuvoton_set32(byte* p, uint32_t v)
{
    p[0] = (byte)(v      );
    p[1] = (byte)(v >>  8);
    p[2] = (byte)(v >> 16);
    p[3] = (byte)(v >> 24);
}

/* Staging for a request whose buffers do not meet the DMA addressing rules.
 * Placed in the default .bss, which the M2354 linker scripts put in the
 * 0x2xxxxxxx SRAM the engine can reach; the assert below is the guard against
 * a linker script that does not. Guarded by the hardware mutex along with the
 * engine itself. */
static ALIGN16 byte nuvotonDmaIn[WOLFSSL_NUVOTON_DMA_BUF_SZ];
static ALIGN16 byte nuvotonDmaOut[WOLFSSL_NUVOTON_DMA_BUF_SZ];

/* Map the port's AES selector onto the BSP AES_MODE_* value. */
static int nuvoton_aes_mode(int mode, uint32_t* opMode)
{
    switch (mode) {
        case WC_NUVOTON_AES_ECB:
            *opMode = AES_MODE_ECB;
            break;
        case WC_NUVOTON_AES_CBC:
            *opMode = AES_MODE_CBC;
            break;
        case WC_NUVOTON_AES_CTR:
            *opMode = AES_MODE_CTR;
            break;
        default:
            /* GCM and CCM do not come through here: they need the GCM packet
             * layout and the feedback buffer, not a plain DMA round. */
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* Map a key length in bytes onto the BSP AES_KEY_SIZE_* value. */
static int nuvoton_aes_keysize(word32 keySz, uint32_t* keySize)
{
    switch (keySz) {
        case 16:
            *keySize = AES_KEY_SIZE_128;
            break;
        case 24:
            *keySize = AES_KEY_SIZE_192;
            break;
        case 32:
            *keySize = AES_KEY_SIZE_256;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* One DMA round over at most WOLFSSL_NUVOTON_DMA_BUF_SZ bytes. The caller has
 * the mutex and has already programmed the key; this sets the IV, runs the
 * round and leaves the chained IV in AES_FDBCK for the next one. */
static int nuvoton_aes_round(uint32_t ctl, const byte* in, byte* out,
    word32 sz, const uint32_t iv[4])
{
    word32      timeout;
    const byte* src = in;
    byte*       dst = out;

    /* Stage anything the engine cannot address itself. */
    if (!nuvoton_dma_ok(in, sz)) {
        XMEMCPY(nuvotonDmaIn, in, sz);
        src = nuvotonDmaIn;
    }
    if (!nuvoton_dma_ok(out, sz)) {
        dst = nuvotonDmaOut;
    }

    CRPT->AES_CTL = ctl;

    AES_SetInitVect(CRPT, 0, iv);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)(uintptr_t)src,
        (uint32_t)(uintptr_t)dst, sz);

    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;

    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);

    timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
    while ((CRPT->INTSTS &
            (CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk)) == 0) {
        if (timeout-- == 0) {
            WOLFSSL_MSG("Nuvoton: AES timeout");
            return WC_TIMEOUT_E;
        }
    }

    if ((CRPT->INTSTS & CRPT_INTSTS_AESEIF_Msk) != 0) {
        WOLFSSL_MSG("Nuvoton: AES error interrupt");
        CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;
        return WC_HW_E;
    }

    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;

    if (dst != out) {
        XMEMCPY(out, nuvotonDmaOut, sz);
    }

    return 0;
}

int wc_nuvoton_hw_aes(wc_NuvotonAesReq* req)
{
    int      ret;
    uint32_t opMode = 0;
    uint32_t keySize = 0;
    uint32_t ctl;
    uint32_t iv[4];
    uint32_t keyWords[8];
    word32   done;
    word32   chunk;

    if (req == NULL || req->in == NULL || req->out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->sz == 0 || (req->sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_LENGTH_E;
    }
    if (req->keySlot == WC_NUVOTON_NO_SLOT && req->key == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_aes_mode(req->mode, &opMode);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_aes_keysize(req->keySz, &keySize);
    if (ret != 0) {
        return ret;
    }
    if (req->mode != WC_NUVOTON_AES_ECB && req->iv == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(keyWords, 0, sizeof(keyWords));
    if (req->key != NULL) {
        for (done = 0; done < req->keySz; done += 4) {
            keyWords[done / 4] = nuvoton_get32(req->key + done);
        }
    }

    XMEMSET(iv, 0, sizeof(iv));
    if (req->iv != NULL) {
        for (done = 0; done < WC_AES_BLOCK_SIZE; done += 4) {
            iv[done / 4] = nuvoton_get32(req->iv + done);
        }
    }

    /* KINSWAP goes with the key words built above; INSWAP and OUTSWAP say the
     * message is little-endian in memory. */
    ctl = ((uint32_t)req->encrypt << CRPT_AES_CTL_ENCRPT_Pos) |
          (opMode  << CRPT_AES_CTL_OPMODE_Pos) |
          (keySize << CRPT_AES_CTL_KEYSZ_Pos)  |
          (AES_IN_OUT_SWAP << CRPT_AES_CTL_OUTSWAP_Pos) |
          CRPT_AES_CTL_KINSWAP_Msk |
          CRPT_AES_CTL_DMAEN_Msk;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(keyWords, sizeof(keyWords));
        return ret;
    }

    /* Stop whatever the engine was doing, then load the key once: the CTL
     * writes below do not disturb the key registers. */
    CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        AES_SetKey(CRPT, 0, keyWords, keySize);
    }
    else {
#ifdef WOLFSSL_NUVOTON_KS
        KS_MEM_Type mem;

        ret = nuvoton_ks_mem(req->keyMem, &mem);
        if (ret == 0) {
            /* The engine reads the key straight out of the store, so it never
             * appears in memory the CPU can see. */
            AES_SetKey_KS(CRPT, mem, (int32_t)req->keySlot);
        }
#else
        ret = BAD_FUNC_ARG;
#endif
    }

    for (done = 0; ret == 0 && done < req->sz; done += chunk) {
        chunk = req->sz - done;
        if (chunk > WOLFSSL_NUVOTON_DMA_BUF_SZ) {
            chunk = WOLFSSL_NUVOTON_DMA_BUF_SZ;
        }

        ret = nuvoton_aes_round(ctl, req->in + done, req->out + done, chunk,
            iv);
        if (ret != 0) {
            break;
        }

        /* AES_FDBCK holds what the engine would feed AES_IV for the next
         * block, so it carries CBC chaining and the CTR counter across chunks
         * without the port having to reconstruct either. */
        iv[0] = CRPT->AES_FDBCK[0];
        iv[1] = CRPT->AES_FDBCK[1];
        iv[2] = CRPT->AES_FDBCK[2];
        iv[3] = CRPT->AES_FDBCK[3];
    }

    /* Hand the chained IV back so the next call continues the stream. */
    if (ret == 0 && req->iv != NULL) {
        for (done = 0; done < WC_AES_BLOCK_SIZE; done += 4) {
            nuvoton_set32(req->iv + done, iv[done / 4]);
        }
    }

    CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;

    ForceZero(keyWords, sizeof(keyWords));
    ForceZero(nuvotonDmaIn, sizeof(nuvotonDmaIn));
    ForceZero(nuvotonDmaOut, sizeof(nuvotonDmaOut));

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_CIPHER */


#if defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA)

/* The BSP public key drivers block on a flag that only the CRPT interrupt
 * sets, so the application has to route that interrupt to ECC_DriverISR().
 * The wait loops carry their own timeout and give up rather than hang, but
 * without the handler every public key operation times out. The port reports
 * that as an error rather than declining to software, because a missing
 * handler is a wiring mistake and a silent slow fallback would hide it.
 * IDE/Nuvoton/M2354 installs the handler; the port README says so too. */

#endif /* WOLFSSL_NUVOTON_ECC || WOLFSSL_NUVOTON_RSA */

#ifdef WOLFSSL_NUVOTON_ECC

/* Map the port's curve selector onto the BSP E_ECC_CURVE value. */
static int nuvoton_ecc_curve(int curveId, E_ECC_CURVE* curve)
{
    switch (curveId) {
        case WC_NUVOTON_CURVE_P192:
            *curve = CURVE_P_192;
            break;
        case WC_NUVOTON_CURVE_P224:
            *curve = CURVE_P_224;
            break;
        case WC_NUVOTON_CURVE_P256:
            *curve = CURVE_P_256;
            break;
        case WC_NUVOTON_CURVE_P384:
            *curve = CURVE_P_384;
            break;
        case WC_NUVOTON_CURVE_P521:
            *curve = CURVE_P_521;
            break;
        case WC_NUVOTON_CURVE_BP256:
            *curve = CURVE_BP_256;
            break;
        case WC_NUVOTON_CURVE_BP384:
            *curve = CURVE_BP_384;
            break;
        case WC_NUVOTON_CURVE_BP512:
            *curve = CURVE_BP_512;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_sign(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->msg == NULL || req->r == NULL ||
        req->s == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        if (req->d == NULL || req->k == NULL) {
            return BAD_FUNC_ARG;
        }
    }
    else if (req->kSlot == WC_NUVOTON_NO_SLOT) {
        /* The engine reads the per-message random out of the store too when
         * the private key lives there; it has no path that mixes the two. */
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        rc = ECC_GenerateSignature(CRPT, curve, req->msg, req->d, req->k,
            req->r, req->s);
    }
    else {
        rc = ECC_GenerateSignature_KS(CRPT, curve, req->msg,
            (KS_MEM_Type)req->keyMem, (int32_t)req->keySlot,
            (KS_MEM_Type)req->keyMem, (int32_t)req->kSlot,
            req->r, req->s);
    }

    wolfSSL_CryptHwMutexUnLock();

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: ECC sign failed");
        return WC_HW_E;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_verify(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->msg == NULL || req->qx == NULL ||
        req->qy == NULL || req->r == NULL || req->s == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    rc = ECC_VerifySignature(CRPT, curve, req->msg, req->qx, req->qy, req->r,
        req->s);

    wolfSSL_CryptHwMutexUnLock();

    /* The driver folds "the signature does not check out" and "the engine
     * failed" into the same negative return, so the caller cannot tell them
     * apart and neither can this. Report it as a failed verify, which is the
     * safe reading of the two. */
    if (rc != 0) {
        return SIG_VERIFY_E;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_shared(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->qx == NULL || req->qy == NULL ||
        req->out == NULL || req->d == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot != WC_NUVOTON_NO_SLOT) {
        /* ECC_GenerateSecretZ_KS() leaves the shared secret in a Key Store
         * slot and hands nothing back, so there is no way to satisfy a caller
         * that asked for the bytes. */
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    rc = ECC_GenerateSecretZ(CRPT, curve, req->d, req->qx, req->qy, req->out);

    wolfSSL_CryptHwMutexUnLock();

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: ECDH failed");
        return WC_HW_E;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_pubkey(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->qx == NULL || req->qy == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot == WC_NUVOTON_NO_SLOT && req->d == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        rc = ECC_GeneratePublicKey(CRPT, curve, req->d, req->qx, req->qy);
    }
    else {
        rc = ECC_GeneratePublicKey_KS(CRPT, curve, (KS_MEM_Type)req->keyMem,
            req->keySlot, req->qx, req->qy, 0);
    }

    wolfSSL_CryptHwMutexUnLock();

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: ECC public key failed");
        return WC_HW_E;
    }

    return 0;
}

#endif /* WOLFSSL_NUVOTON_ECC */

#ifdef WOLFSSL_NUVOTON_RSA

/* Map a modulus size in bits onto the BSP RSA_KEY_SIZE_* value. */
static int nuvoton_rsa_keysize(int keyBits, uint32_t* keySize)
{
    switch (keyBits) {
        case 1024:
            *keySize = RSA_KEY_SIZE_1024;
            break;
        case 2048:
            *keySize = RSA_KEY_SIZE_2048;
            break;
        case 3072:
            *keySize = RSA_KEY_SIZE_3072;
            break;
        case 4096:
            *keySize = RSA_KEY_SIZE_4096;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_rsa(wc_NuvotonRsaReq* req)
{
    int             ret;
    int32_t         rc;
    uint32_t        keySize = 0;
    uint32_t        opMode;
    word32          timeout;
    RSA_BUF_NORMAL_T* buf;

    if (req == NULL || req->in == NULL || req->n == NULL || req->e == NULL ||
        req->out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot != WC_NUVOTON_NO_SLOT) {
        /* The Key Store form of RSA wants every CRT factor in its own slot,
         * which nuvoton_key.c does not provision yet. */
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_rsa_keysize(req->keyBits, &keySize);
    if (ret != 0) {
        return ret;
    }

    /* The engine works out of a caller supplied scratch area: two kilobytes
     * for the plain mode, and more for CRT. Too big for the stack on a part
     * with this much SRAM, so it comes off the heap for the one call. */
    buf = (RSA_BUF_NORMAL_T*)XMALLOC(sizeof(RSA_BUF_NORMAL_T), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return MEMORY_E;
    }

    /* Only the plain modular exponentiation is wired up. CRT needs p, q and
     * the four precomputed values in the CRT working buffer, and a private
     * operation is correct either way, just slower. */
    opMode = RSA_MODE_NORMAL;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    rc = RSA_Open(CRPT, opMode, keySize, buf, sizeof(RSA_BUF_NORMAL_T), 0);
    if (rc == 0) {
        rc = RSA_SetKey(CRPT, req->e);
    }
    if (rc == 0) {
        rc = RSA_SetDMATransfer(CRPT, req->in, req->n, NULL, NULL);
    }
    if (rc == 0) {
        CRPT->INTSTS = CRPT_INTSTS_RSAIF_Msk | CRPT_INTSTS_RSAEIF_Msk;
        RSA_Start(CRPT);

        timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
        while ((CRPT->INTSTS &
                (CRPT_INTSTS_RSAIF_Msk | CRPT_INTSTS_RSAEIF_Msk)) == 0) {
            if (timeout-- == 0) {
                WOLFSSL_MSG("Nuvoton: RSA timeout");
                rc = -1;
                break;
            }
        }

        if (rc == 0 && (CRPT->INTSTS & CRPT_INTSTS_RSAEIF_Msk) != 0) {
            WOLFSSL_MSG("Nuvoton: RSA error interrupt");
            rc = -1;
        }

        CRPT->INTSTS = CRPT_INTSTS_RSAIF_Msk | CRPT_INTSTS_RSAEIF_Msk;
    }
    if (rc == 0) {
        rc = RSA_Read(CRPT, req->out);
    }

    wolfSSL_CryptHwMutexUnLock();

    ForceZero(buf, sizeof(RSA_BUF_NORMAL_T));
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: RSA failed");
        return WC_HW_E;
    }

    return 0;
}

#endif /* WOLFSSL_NUVOTON_RSA */


#ifdef WOLFSSL_NUVOTON_KS

/* The store records the key size as an index, not a bit count. */
static int nuvoton_ks_size_meta(word32 bits, uint32_t* meta)
{
    switch (bits) {
        case 128:  *meta = KS_META_128;  break;
        case 163:  *meta = KS_META_163;  break;
        case 192:  *meta = KS_META_192;  break;
        case 224:  *meta = KS_META_224;  break;
        case 233:  *meta = KS_META_233;  break;
        case 255:  *meta = KS_META_255;  break;
        case 256:  *meta = KS_META_256;  break;
        case 283:  *meta = KS_META_283;  break;
        case 384:  *meta = KS_META_384;  break;
        case 409:  *meta = KS_META_409;  break;
        case 512:  *meta = KS_META_512;  break;
        case 521:  *meta = KS_META_521;  break;
        case 571:  *meta = KS_META_571;  break;
        case 1024: *meta = KS_META_1024; break;
        case 1536: *meta = KS_META_1536; break;
        case 2048: *meta = KS_META_2048; break;
        case 3072: *meta = KS_META_3072; break;
        case 4096: *meta = KS_META_4096; break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* Which engine is allowed to use the key. The store refuses any other. */
static int nuvoton_ks_owner_meta(int owner, uint32_t* meta)
{
    switch (owner) {
        case 0: *meta = KS_META_AES;     break;
        case 1: *meta = KS_META_HMAC;    break;
        case 2: *meta = KS_META_RSA_EXP; break;
        case 3: *meta = KS_META_RSA_MID; break;
        case 4: *meta = KS_META_ECC;     break;
        case 5: *meta = KS_META_CPU;     break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_ks_write(wc_NuvotonKsWriteReq* req)
{
    int         ret;
    int32_t     slot;
    KS_MEM_Type mem;
    uint32_t    meta;
    uint32_t    sizeMeta = 0;
    uint32_t    ownerMeta = 0;
    /* The largest key the store holds is 4096 bits. */
    uint32_t    words[4096 / 32];

    if (req == NULL || req->key == NULL || req->keySz == 0 ||
        req->keySz > sizeof(words)) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ks_mem(req->keyMem, &mem);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_ks_size_meta(req->bits, &sizeMeta);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_ks_owner_meta(req->owner, &ownerMeta);
    if (ret != 0) {
        return ret;
    }

    /* Everything the port writes is a secure key. READABLE is the caller's
     * choice and is what separates a key software can get back from one that
     * only ever leaves the store into an engine. */
    meta = sizeMeta | ownerMeta | KS_META_SECURE;
    if (req->readable) {
        meta |= KS_META_READABLE;
    }

    XMEMSET(words, 0, sizeof(words));
    XMEMCPY(words, req->key, req->keySz);

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(words, sizeof(words));
        return ret;
    }

    slot = KS_Write(mem, meta, words);

    wolfSSL_CryptHwMutexUnLock();

    ForceZero(words, sizeof(words));

    if (slot < 0) {
        WOLFSSL_MSG("Nuvoton: KS_Write failed");
        return WC_HW_E;
    }

    return (int)slot;
}

int wc_nuvoton_hw_ks_read(int keyMem, int keySlot, byte* out, word32 outSz)
{
    int         ret;
    KS_MEM_Type mem;
    uint32_t    words[4096 / 32];

    if (out == NULL || outSz == 0 || outSz > sizeof(words)) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ks_mem(keyMem, &mem);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (KS_Read(mem, (int32_t)keySlot, words, (outSz + 3) / 4) != 0) {
        WOLFSSL_MSG("Nuvoton: KS_Read failed");
        ret = WC_HW_E;
    }
    else {
        XMEMCPY(out, words, outSz);
    }

    wolfSSL_CryptHwMutexUnLock();

    ForceZero(words, sizeof(words));

    return ret;
}

int wc_nuvoton_hw_ks_erase(int keyMem, int keySlot)
{
    int         ret;
    KS_MEM_Type mem;

    ret = nuvoton_ks_mem(keyMem, &mem);
    if (ret != 0) {
        return ret;
    }

    /* KS_EraseKey() writes KS_SRAM into the metadata itself, so it can only
     * clear a volatile slot. A Flash or OTP key is retired with
     * wc_nuvoton_hw_ks_revoke() instead; there is no per key erase for
     * those. */
    if (mem != KS_SRAM) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (KS_EraseKey((int32_t)keySlot) != 0) {
        WOLFSSL_MSG("Nuvoton: KS_EraseKey failed");
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_nuvoton_hw_ks_revoke(int keyMem, int keySlot)
{
    int         ret;
    KS_MEM_Type mem;

    ret = nuvoton_ks_mem(keyMem, &mem);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (KS_RevokeKey(mem, (int32_t)keySlot) != 0) {
        WOLFSSL_MSG("Nuvoton: KS_RevokeKey failed");
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_KS */

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_SECURE */
