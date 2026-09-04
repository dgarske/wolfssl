/* ele_settings.h
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

/* Macro-only settings for the NXP EdgeLock Secure Enclave (ELE) port.
 *
 * Pulled in early from wolfssl/wolfcrypt/settings.h so the unmodified
 * wolfcrypt/test and wolfcrypt/benchmark route to the device without source
 * changes. Deliberately free of any BSP or vendor header.
 */

#ifndef WOLFSSL_NXP_ELE_SETTINGS_H
#define WOLFSSL_NXP_ELE_SETTINGS_H

#ifdef WOLFSSL_NXP_ELE

/* The port is implemented as a crypto callback device. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* Device id for the enclave. 0x454C45 is ASCII "ELE"; distinct from the
 * ids already claimed by other ports (CAAM 7, SECO/ARIA 8, MAX3266X 9,
 * HUK 810, STSAFE 0x53545341, VaultIC 0x564C5443, TROPIC01 0x75757,
 * Versal Gen2 ASU 0x4153). */
#ifndef WOLFSSL_NXP_ELE_DEVID
    #define WOLFSSL_NXP_ELE_DEVID 0x454C45
#endif

/* Character device exposing the enclave's true random number generator.
 * On i.MX93/i.MX95 the fsl-se driver registers the enclave TRNG as the
 * system hwrng; confirm with
 *     cat /sys/class/misc/hw_random/rng_current      -> ele-trng
 * Note the node is root-only by default. */
#ifndef WOLFSSL_NXP_ELE_TRNG_DEVICE
    #define WOLFSSL_NXP_ELE_TRNG_DEVICE "/dev/hwrng"
#endif

/* Enable the TRNG sub-feature by default; others are opt-in as they land. */
#if !defined(WOLFSSL_NXP_ELE_TRNG) && !defined(WOLFSSL_NXP_ELE_NO_TRNG)
    #define WOLFSSL_NXP_ELE_TRNG
#endif

/* Route the stock test and benchmark applications at the enclave. */
#if !defined(WC_USE_DEVID) && !defined(WOLFSSL_NXP_ELE_NO_DEVID)
    #define WC_USE_DEVID WOLFSSL_NXP_ELE_DEVID
#endif

#endif /* WOLFSSL_NXP_ELE */
#endif /* WOLFSSL_NXP_ELE_SETTINGS_H */
