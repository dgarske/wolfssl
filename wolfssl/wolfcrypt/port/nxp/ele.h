/* ele.h
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

#ifndef WOLFSSL_NXP_ELE_H
#define WOLFSSL_NXP_ELE_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_NXP_ELE

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Fill buf with sz bytes from the EdgeLock Secure Enclave TRNG.
 * Returns 0 on success, or WC_HW_E / RNG_FAILURE_E on error. */
WOLFSSL_LOCAL int wc_ele_trng_read(byte* buf, word32 sz);

/* Release any file descriptor cached by wc_ele_trng_read(). */

/* Crypto callback entry point. Returns CRYPTOCB_UNAVAILABLE for anything the
 * enclave does not implement so wolfCrypt falls back to software. */
WOLFSSL_LOCAL int wc_EleCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx);

/* Register/unregister the enclave as a crypto callback device. Pass
 * INVALID_DEVID to use WOLFSSL_NXP_ELE_DEVID. */
WOLFSSL_API int wc_EleCryptoCb_RegisterDevice(int devId);
WOLFSSL_API void wc_EleCryptoCb_UnRegisterDevice(int devId);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_NXP_ELE */
#endif /* WOLFSSL_NXP_ELE_H */
