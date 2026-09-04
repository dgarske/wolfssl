/* nuvoton_cryptocb.h
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

/* Crypto callback device for the Nuvoton NuMicro M2354.
 *
 * The application brings the device up once, after wolfCrypt_Init():
 *
 *     wolfCrypt_Init();
 *     wc_NuvotonCryptoCb_RegisterDevice(WOLFSSL_NUVOTON_DEVID);
 *
 * and then passes WOLFSSL_NUVOTON_DEVID as the devId of any key or hash it
 * wants run on the hardware, or calls wolfSSL_CTX_SetDevId() to route a whole
 * TLS context. Anything the CRPT accelerator cannot do is declined and runs in
 * software instead, so a build does not have to know in advance which curves
 * or modes the part supports.
 */

#ifndef WOLF_CRYPT_NUVOTON_CRYPTOCB_H
#define WOLF_CRYPT_NUVOTON_CRYPTOCB_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Bring the hardware up and register the device with the crypto callback
 * framework. Returns 0, or a wolfCrypt error if the hardware would not
 * start. */
WOLFSSL_API int wc_NuvotonCryptoCb_RegisterDevice(int devId);

/* Unregister the device and release the hardware. */
WOLFSSL_API void wc_NuvotonCryptoCb_UnRegisterDevice(int devId);

/* The callback itself. Registered by wc_NuvotonCryptoCb_RegisterDevice(); it
 * is public so an application that wants to wrap or chain it can. */
WOLFSSL_API int wc_NuvotonCryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);

/* Per engine entry points, one per wc_AlgoType the port handles. Each returns
 * 0 when the hardware did the work, CRYPTOCB_UNAVAILABLE to fall back to
 * software, or a wolfCrypt error. */
WOLFSSL_LOCAL int wc_NuvotonCb_Rng(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_NuvotonCb_Seed(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_NuvotonCb_Hash(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_NuvotonCb_HashCopy(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_NuvotonCb_Cipher(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_NuvotonCb_Pk(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_NuvotonCb_Free(wc_CryptoInfo* info);

/* Release what a hash context is holding. Called by wc_NuvotonCb_Free() for a
 * WC_ALGO_TYPE_HASH object, and declines so wolfCrypt still wipes it. */
WOLFSSL_LOCAL int wc_NuvotonHashFree(wc_CryptoInfo* info);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_NUVOTON_M2354 && WOLF_CRYPTO_CB */

#endif /* WOLF_CRYPT_NUVOTON_CRYPTOCB_H */
