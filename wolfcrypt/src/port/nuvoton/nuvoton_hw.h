/* nuvoton_hw.h
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

/* The TrustZone boundary for the Nuvoton NuMicro M2354 port.
 *
 * Every touch of the CRPT accelerator, the TRNG and the Key Store goes through
 * one of the wc_nuvoton_hw_* calls declared here, and nothing else in the port
 * includes a BSP header. That leaves exactly one seam to move when wolfCrypt
 * changes worlds:
 *
 *   WOLFSSL_NUVOTON_SECURE  nuvoton_hw.c is compiled and implements these
 *                           against the BSP StdDriver, in the secure world.
 *   WOLFSSL_NUVOTON_NSC     nuvoton_hw.c is not compiled. The same prototypes
 *                           are satisfied by cmse_nonsecure_entry veneers in a
 *                           secure partition, which call the identical
 *                           nuvoton_hw.c compiled on that side. See
 *                           IDE/Nuvoton/M2354/secure/.
 *
 * The declarations therefore use only wolfSSL types: no CRPT_T, no
 * E_ECC_CURVE, no KS_MEM_Type. Requests with more than a handful of arguments
 * are passed by pointer to a struct, which keeps the veneer signatures short
 * and gives the secure side a single address range to validate with
 * cmse_check_address_range().
 *
 * This header is port private and is not installed.
 */

#ifndef WOLF_CRYPT_NUVOTON_HW_H
#define WOLF_CRYPT_NUVOTON_HW_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_NUVOTON_M2354

#include <wolfssl/wolfcrypt/types.h>

/* Secure side of a TrustZone split. nuvoton_hw.c is compiled into the secure
 * image next to the veneers in IDE/Nuvoton/M2354/secure/, which export these
 * same names to the non-secure world. Rename the implementations so both can
 * live in one image; each veneer validates its pointers and then calls the
 * matching _s function. Nothing else changes, so the secure and non-secure
 * builds share one source file. */
#ifdef WOLFSSL_NUVOTON_NSC_IMPL
    #define wc_nuvoton_hw_init        wc_nuvoton_hw_init_s
    #define wc_nuvoton_hw_cleanup     wc_nuvoton_hw_cleanup_s
    #define wc_nuvoton_hw_trng        wc_nuvoton_hw_trng_s
    #define wc_nuvoton_hw_sha         wc_nuvoton_hw_sha_s
    #define wc_nuvoton_hw_aes         wc_nuvoton_hw_aes_s
    #define wc_nuvoton_hw_ecc_sign    wc_nuvoton_hw_ecc_sign_s
    #define wc_nuvoton_hw_ecc_verify  wc_nuvoton_hw_ecc_verify_s
    #define wc_nuvoton_hw_ecc_shared  wc_nuvoton_hw_ecc_shared_s
    #define wc_nuvoton_hw_ecc_pubkey  wc_nuvoton_hw_ecc_pubkey_s
    #define wc_nuvoton_hw_rsa         wc_nuvoton_hw_rsa_s
    #define wc_nuvoton_hw_ks_write    wc_nuvoton_hw_ks_write_s
    #define wc_nuvoton_hw_ks_read     wc_nuvoton_hw_ks_read_s
    #define wc_nuvoton_hw_ks_erase    wc_nuvoton_hw_ks_erase_s
    #define wc_nuvoton_hw_ks_revoke   wc_nuvoton_hw_ks_revoke_s
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Hash algorithms the CRPT SHA engine implements. Mapped to the BSP
 * SHA_MODE_* values inside nuvoton_hw.c. */
enum wc_NuvotonShaMode {
    WC_NUVOTON_SHA_1    = 0,
    WC_NUVOTON_SHA_224  = 1,
    WC_NUVOTON_SHA_256  = 2,
    WC_NUVOTON_SHA_384  = 3,
    WC_NUVOTON_SHA_512  = 4
};

/* Where a chunk sits in a SHA cascade. A message small enough to be hashed in
 * one call uses WC_NUVOTON_DMA_ONE_SHOT; a streaming update runs FIRST, then
 * CONTINUE for each further block, then LAST. Mapped to the BSP CRYPTO_DMA_*
 * values inside nuvoton_hw.c. */
enum wc_NuvotonDmaMode {
    WC_NUVOTON_DMA_ONE_SHOT = 0,
    WC_NUVOTON_DMA_FIRST    = 1,
    WC_NUVOTON_DMA_CONTINUE = 2,
    WC_NUVOTON_DMA_LAST     = 3
};

/* AES modes the CRPT engine implements and this port offers. */
enum wc_NuvotonAesMode {
    WC_NUVOTON_AES_ECB = 0,
    WC_NUVOTON_AES_CBC = 1,
    WC_NUVOTON_AES_CTR = 2,
    WC_NUVOTON_AES_GCM = 3,
    WC_NUVOTON_AES_CCM = 4
};

/* Key Store memory types. Mirrors the BSP KS_MEM_Type values so the port never
 * has to name that enum, but the mapping is made explicit in nuvoton_hw.c
 * rather than assumed. */
enum wc_NuvotonKsMem {
    WC_NUVOTON_KS_SRAM  = 0,
    WC_NUVOTON_KS_FLASH = 1,
    WC_NUVOTON_KS_OTP   = 2
};

/* Curves the CRPT ECC engine implements, limited to the ones this port maps
 * from a wolfCrypt curve id. Mapped to E_ECC_CURVE inside nuvoton_hw.c. */
enum wc_NuvotonCurve {
    WC_NUVOTON_CURVE_NONE  = 0,
    WC_NUVOTON_CURVE_P192  = 1,
    WC_NUVOTON_CURVE_P224  = 2,
    WC_NUVOTON_CURVE_P256  = 3,
    WC_NUVOTON_CURVE_P384  = 4,
    WC_NUVOTON_CURVE_P521  = 5,
    WC_NUVOTON_CURVE_BP256 = 6,
    WC_NUVOTON_CURVE_BP384 = 7,
    WC_NUVOTON_CURVE_BP512 = 8
};

/* No Key Store slot: the request carries plain key material instead. */
#define WC_NUVOTON_NO_SLOT (-1)

/* One AES request. in and out may alias. sz is a whole number of blocks; the
 * caller keeps any partial tail. iv is read and written back for the chaining
 * modes and ignored for ECB. Either key/keySz or (keyMem, keySlot) supplies the
 * key, never both. */
typedef struct wc_NuvotonAesReq {
    const byte* in;
    byte*       out;
    const byte* key;      /* NULL when keySlot is not WC_NUVOTON_NO_SLOT */
    byte*       iv;       /* 16 bytes, in and out, NULL for ECB */
    const byte* aad;      /* GCM and CCM only */
    byte*       tag;      /* GCM and CCM only, out on encrypt, in on decrypt */
    word32      sz;
    word32      keySz;    /* 16, 24 or 32 */
    word32      aadSz;
    word32      tagSz;
    int         mode;     /* enum wc_NuvotonAesMode */
    int         encrypt;  /* 1 to encrypt, 0 to decrypt */
    int         keyMem;   /* enum wc_NuvotonKsMem, used when keySlot is set */
    int         keySlot;  /* WC_NUVOTON_NO_SLOT for plain key material */
} wc_NuvotonAesReq;

/* One ECC request. The CRPT driver speaks NUL terminated lowercase hex
 * strings, not byte arrays, so that is what crosses this boundary; the
 * conversion lives in nuvoton_cb_pk.c, which uses the converters wolfCrypt
 * already has. Unused fields are NULL. */
typedef struct wc_NuvotonEccReq {
    char* msg;      /* digest, hex */
    char* d;        /* private key, hex; NULL when keySlot is set */
    char* k;        /* per-message random, hex, sign only; unused when
                     * kSlot is set */
    char* qx;       /* public key X, hex */
    char* qy;       /* public key Y, hex */
    char* r;        /* signature R, hex, in or out */
    char* s;        /* signature S, hex, in or out */
    char* out;      /* shared secret (ECDH), hex */
    int   curveId;  /* enum wc_NuvotonCurve */
    int   keyMem;   /* enum wc_NuvotonKsMem, used when keySlot is set */
    int   keySlot;  /* WC_NUVOTON_NO_SLOT for plain key material */
    int   kSlot;    /* signing from a stored key: the engine wants the
                     * per-message random in a slot of its own, in the same
                     * store. WC_NUVOTON_NO_SLOT otherwise. */
} wc_NuvotonEccReq;

/* One SHA request. A cmse_nonsecure_entry veneer cannot take arguments that
 * spill onto the stack, so anything past four words is packed into a struct
 * the same way the other engines do it. */
typedef struct wc_NuvotonShaReq {
    const byte* in;
    byte*       digest;   /* written for ONE_SHOT and LAST, may be NULL else */
    word32      inSz;
    word32      digestSz;
    int         shaMode;  /* enum wc_NuvotonShaMode */
    int         dmaMode;  /* enum wc_NuvotonDmaMode */
} wc_NuvotonShaReq;

/* One Key Store write. Same reason as above. */
typedef struct wc_NuvotonKsWriteReq {
    const byte* key;
    word32      keySz;
    word32      bits;     /* key size the store records */
    int         keyMem;   /* enum wc_NuvotonKsMem */
    int         owner;    /* which engine may use it, see nuvoton_key.h */
    int         readable; /* 1 to allow reading it back */
} wc_NuvotonKsWriteReq;

/* One RSA modular exponentiation. All values are NUL terminated hex strings,
 * most significant digit first. p and q are set only for a CRT private
 * operation. keyBits is 1024, 2048, 3072 or 4096. */
typedef struct wc_NuvotonRsaReq {
    char*  in;       /* base, hex */
    char*  n;        /* modulus, hex */
    char*  e;        /* exponent, hex; the private exponent for a decrypt */
    char*  p;        /* CRT factor, hex, or NULL */
    char*  q;        /* CRT factor, hex, or NULL */
    char*  out;      /* result, hex */
    word32 outSz;    /* size of out in bytes, including the NUL */
    int    keyBits;
    int    keyMem;   /* enum wc_NuvotonKsMem, used when keySlot is set */
    int    keySlot;  /* WC_NUVOTON_NO_SLOT for plain key material */
} wc_NuvotonRsaReq;

/* Bring the CRPT, TRNG and Key Store blocks up: ungate their clocks, release
 * them from reset and open the drivers. Idempotent, reference counted, and
 * safe to call from more than one thread. Returns 0 or a wolfCrypt error. */
WOLFSSL_LOCAL int wc_nuvoton_hw_init(void);

/* Undo one wc_nuvoton_hw_init(). The hardware is only shut down when the last
 * reference goes away. */
WOLFSSL_LOCAL void wc_nuvoton_hw_cleanup(void);

/* Read sz bytes from the TRNG. */
WOLFSSL_LOCAL int wc_nuvoton_hw_trng(byte* out, word32 sz);

/* Run one step of a SHA cascade. in must be a whole number of blocks unless
 * dmaMode is WC_NUVOTON_DMA_ONE_SHOT or WC_NUVOTON_DMA_LAST.
 *
 * Two error codes mean "the engine cannot take this one", not "the operation
 * failed", and the caller turns them into a crypto callback decline:
 *     BAD_LENGTH_E  inSz is zero, which the engine has no path for
 *     BAD_ALIGN_E   in does not meet the DMA addressing rules */
WOLFSSL_LOCAL int wc_nuvoton_hw_sha(wc_NuvotonShaReq* req);

/* Run one AES request. */
WOLFSSL_LOCAL int wc_nuvoton_hw_aes(wc_NuvotonAesReq* req);

/* ECDSA sign, ECDSA verify, ECDH shared secret, and public key from private.
 * Verify returns 0 when the signature is good and SIG_VERIFY_E when it is
 * not; a hardware failure returns some other error. */
WOLFSSL_LOCAL int wc_nuvoton_hw_ecc_sign(wc_NuvotonEccReq* req);
WOLFSSL_LOCAL int wc_nuvoton_hw_ecc_verify(wc_NuvotonEccReq* req);
WOLFSSL_LOCAL int wc_nuvoton_hw_ecc_shared(wc_NuvotonEccReq* req);
WOLFSSL_LOCAL int wc_nuvoton_hw_ecc_pubkey(wc_NuvotonEccReq* req);

/* One RSA modular exponentiation. */
WOLFSSL_LOCAL int wc_nuvoton_hw_rsa(wc_NuvotonRsaReq* req);

/* Key Store. The metadata word the store wants is built on the BSP side from
 * these, so no BSP macro has to cross the boundary. ks_write returns the slot
 * index it allocated, or a negative wolfCrypt error. */
WOLFSSL_LOCAL int wc_nuvoton_hw_ks_write(wc_NuvotonKsWriteReq* req);
WOLFSSL_LOCAL int wc_nuvoton_hw_ks_read(int keyMem, int keySlot, byte* out,
    word32 outSz);
WOLFSSL_LOCAL int wc_nuvoton_hw_ks_erase(int keyMem, int keySlot);
WOLFSSL_LOCAL int wc_nuvoton_hw_ks_revoke(int keyMem, int keySlot);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_NUVOTON_M2354 */

#endif /* WOLF_CRYPT_NUVOTON_HW_H */
