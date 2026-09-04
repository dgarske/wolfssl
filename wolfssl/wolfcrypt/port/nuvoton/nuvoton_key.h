/* nuvoton_key.h
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

/* Key Store keys on the Nuvoton NuMicro M2354.
 *
 * A key written to the store gets a slot, and from then on the application
 * uses the handle rather than the key. Attach the handle to an Aes or an
 * ecc_key with wc_NuvotonKs_SetAesKey() or wc_NuvotonKs_SetEccKey() and the
 * crypto callback runs the operation with the AES_SetKey_KS and ECC_*_KS
 * driver entry points, so the key material never enters wolfCrypt memory.
 *
 * The handle rides in the standard devCtx field of the object, so no wolfSSL
 * struct grows a member for this.
 */

#ifndef WOLF_CRYPT_NUVOTON_KEY_H
#define WOLF_CRYPT_NUVOTON_KEY_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_KS)

#include <wolfssl/wolfcrypt/types.h>
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Which store a key lives in. Named here rather than exposing the BSP
 * KS_MEM_Type so this header stands on its own. */
typedef enum {
    WC_NUVOTON_KS_MEM_SRAM  = 0, /* volatile, cleared by a reset */
    WC_NUVOTON_KS_MEM_FLASH = 1, /* non-volatile */
    WC_NUVOTON_KS_MEM_OTP   = 2  /* one time programmable */
} wc_NuvotonKsMemType;

/* What the key is allowed to be used for. The store enforces this: a key
 * written for AES cannot be fed to the ECC engine. */
typedef enum {
    WC_NUVOTON_KS_OWNER_AES     = 0,
    WC_NUVOTON_KS_OWNER_HMAC    = 1,
    WC_NUVOTON_KS_OWNER_RSA_EXP = 2,
    WC_NUVOTON_KS_OWNER_RSA_MID = 3,
    WC_NUVOTON_KS_OWNER_ECC     = 4,
    WC_NUVOTON_KS_OWNER_CPU     = 5
} wc_NuvotonKsOwner;

/* A key that lives in the store. Held in the devCtx of the Aes or ecc_key it
 * belongs to; the owner of that object owns this too. */
typedef struct wc_NuvotonKsKey {
    int    slot;    /* index the store gave it */
    int    mem;     /* wc_NuvotonKsMemType */
    int    owner;   /* wc_NuvotonKsOwner */
    word32 bits;    /* key size in bits */
} wc_NuvotonKsKey;

/* Write key material into the store and fill in ksKey with the handle. bits
 * must be one of the sizes the store holds (128, 192, 224, 233, 255, 256, 283,
 * 384, 409, 512, 521, 571, 1024, 1536, 2048, 3072, 4096).
 *
 * readable asks for a key software can read back with wc_NuvotonKs_Read();
 * leave it 0 for anything that should never come out again.
 *
 * OTP slots cannot be rewritten, so a mistake there is permanent. */
WOLFSSL_API int wc_NuvotonKs_Write(wc_NuvotonKsKey* ksKey, int mem, int owner,
    word32 bits, const byte* key, word32 keySz, int readable);

/* Read a key back. Only works for a slot written with readable set. */
WOLFSSL_API int wc_NuvotonKs_Read(const wc_NuvotonKsKey* ksKey, byte* out,
    word32 outSz);

/* Clear a volatile slot. The store has no per key erase for Flash or OTP;
 * use wc_NuvotonKs_Revoke() for those. */
WOLFSSL_API int wc_NuvotonKs_Erase(const wc_NuvotonKsKey* ksKey);

/* Retire a key permanently. Works for every store, and cannot be undone. */
WOLFSSL_API int wc_NuvotonKs_Revoke(const wc_NuvotonKsKey* ksKey);

#ifndef NO_AES
/* Point an Aes at a stored key. The Aes must already carry the port's device
 * id. ksKey has to outlive the Aes. */
WOLFSSL_API int wc_NuvotonKs_SetAesKey(Aes* aes, wc_NuvotonKsKey* ksKey);
#endif

#ifdef HAVE_ECC
/* Point an ecc_key at a stored private key, and set the curve. ksKey has to
 * outlive the ecc_key. */
WOLFSSL_API int wc_NuvotonKs_SetEccKey(ecc_key* key, wc_NuvotonKsKey* ksKey,
    int curveId);
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_KS */

#endif /* WOLF_CRYPT_NUVOTON_KEY_H */
