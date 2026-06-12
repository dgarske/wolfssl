/* amebapro2.h
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

/* RealTek AmebaPro2 (RTL8735B) HUK (Hardware Unique Key) crypto-callback port.
 *
 * Binds keys to the silicon HUK via the AmebaPro2 HAL crypto engine: a 256-bit
 * "seed" is run through the HAL HKDF key-ladder against the HUK to land a
 * device-bound working key in a secure key-storage slot; AES (GCM/ECB/CBC) then
 * runs from that slot without the key ever entering software. ECDSA sign binds
 * a HUK-derived (or OTP-resident) private key. This mirrors the vendor-neutral
 * DHUK crypto-callback device the STM32 port provides (wc_Stm32_DhukRegister),
 * reusing the generic WOLFSSL_DHUK plumbing in ecc.c / ecc.h.
 */

#ifndef _WOLFPORT_AMEBAPRO2_H_
#define _WOLFPORT_AMEBAPRO2_H_

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_REALTEK_HUK

/* The RealTek HUK device reuses the generic DHUK seed / wrapped-key plumbing
 * (ecc_key fields, wc_ecc_import_wrapped_private, free-path scrub). Turn on the
 * vendor-neutral switch if the user only set WOLFSSL_REALTEK_HUK. This must be
 * visible before ecc.h evaluates the shared guards. */
#if !defined(WOLFSSL_DHUK)
    #define WOLFSSL_DHUK
#endif

/* Transparent HUK crypto flows through the crypto-callback framework. */
#if !defined(WOLF_CRYPTO_CB)
    #error "WOLFSSL_REALTEK_HUK requires WOLF_CRYPTO_CB (crypto callback dispatch)"
#endif

/* Crypto-callback device id for transparent HUK crypto. Distinct from the
 * STM32 DHUK device (808). Override before include if it collides. */
#ifndef WC_HUK_DEVID
    #define WC_HUK_DEVID                    809
#endif

/* Secure key-storage slot numbers used by the key ladder (HKDF_KEY_STG_IDX_*
 * in the HAL). The HUK source slot is HUK1 (==1); HUK2 is 2; slots 3..8 are
 * general write-back slots. The PRK lands in one slot, the derived working key
 * in another -- the working-key slot is the one AES *_sk_init references. All
 * overridable from user_settings. */
#ifndef WC_AMEBAPRO2_HUK_SK_IDX
    #define WC_AMEBAPRO2_HUK_SK_IDX        1   /* HKDF_KEY_STG_IDX_HUK1 */
#endif
#ifndef WC_AMEBAPRO2_HKDF_PRK_IDX
    #define WC_AMEBAPRO2_HKDF_PRK_IDX      3   /* HKDF_KEY_STG_IDX_3 */
#endif
#ifndef WC_AMEBAPRO2_DERIVED_WB_IDX
    #define WC_AMEBAPRO2_DERIVED_WB_IDX    4   /* HKDF_KEY_STG_IDX_4 */
#endif

/* crypto_sel for hal_hkdf_hmac_sha256_secure_init: HKDF_CRYPTO_HW_SEL_EN. */
#ifndef WC_AMEBAPRO2_HKDF_CRYPTO_SEL
    #define WC_AMEBAPRO2_HKDF_CRYPTO_SEL   0
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Register / unregister the AmebaPro2 HUK device. After registering at
 * WC_HUK_DEVID, set an object's devId to it at init (e.g.
 * wc_AesInit(&aes, NULL, WC_HUK_DEVID)) to route transparently to the HUK
 * crypto engine. Returns 0 on success. */
WOLFSSL_API int  wc_AmebaPro2_HukRegister(int devId);
WOLFSSL_API void wc_AmebaPro2_HukUnRegister(int devId);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_REALTEK_HUK */

#endif /* _WOLFPORT_AMEBAPRO2_H_ */
