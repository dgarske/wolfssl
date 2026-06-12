/* amebapro2_shim.h
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

/* Host compile-test stand-in for the slice of the RealTek AmebaPro2 HAL that
 * wolfcrypt/src/port/realtek/amebapro2.c references. Compiled ONLY under
 * WOLFSSL_AMEBAPRO2_HOST_TEST (set by --enable-amebapro2). It lets the
 * crypto-callback dispatch, field access, and compile-time guards be exercised
 * on a host without the customer SDK. Every stub returns a success sentinel; it
 * performs NO real crypto. On target this header is NOT used -- the real HAL
 * headers (hal_crypto.h, hal_hkdf.h) are included instead, supplied via the
 * application/board include path.
 *
 * The prototypes here intentionally mirror the real HAL signatures from
 * nuwa_hal_realtek (rtl8735b branch),
 * ameba/amebapro2/source/fwlib/rtl8735b/include/. Keep this in sync with the
 * HAL calls in amebapro2.c (add a stub here when the port starts calling a new
 * HAL function under host test).
 */

#ifndef _WOLFPORT_AMEBAPRO2_SHIM_H_
#define _WOLFPORT_AMEBAPRO2_SHIM_H_

#ifdef WOLFSSL_AMEBAPRO2_HOST_TEST

/* HAL scalar types (the real HAL pulls these from its basic_types header). */
#ifndef _RTL8735B_TYPES_SHIMMED_
    #define _RTL8735B_TYPES_SHIMMED_
    typedef unsigned char  u8;
    typedef unsigned int   u32;
#endif

/* hal_status_t / success sentinel. */
typedef int hal_status_t;
#ifndef HAL_OK
    #define HAL_OK 0
#endif

/* ---- Engine + AES secure-key ops (hal_crypto.h) ---- */
static inline int hal_crypto_engine_init(void) { return 0; }
static inline int hal_crypto_aes_gcm_sk_init(u8 key_num, const u32 keylen)
    { (void)key_num; (void)keylen; return 0; }
static inline int hal_crypto_aes_gcm_encrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u8* aad, const u32 aadlen, u8* pResult, u8* pTag)
    { (void)msg; (void)msglen; (void)iv; (void)aad; (void)aadlen;
      (void)pResult; (void)pTag; return 0; }
static inline int hal_crypto_aes_gcm_decrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u8* aad, const u32 aadlen, u8* pResult, u8* pTag)
    { (void)msg; (void)msglen; (void)iv; (void)aad; (void)aadlen;
      (void)pResult; (void)pTag; return 0; }
static inline int hal_crypto_aes_ecb_sk_init(u8 key_num, const u32 keylen)
    { (void)key_num; (void)keylen; return 0; }
static inline int hal_crypto_aes_ecb_encrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u32 ivlen, u8* pResult)
    { (void)msg; (void)msglen; (void)iv; (void)ivlen; (void)pResult; return 0; }
static inline int hal_crypto_aes_ecb_decrypt(const u8* msg, const u32 msglen,
        const u8* iv, const u32 ivlen, u8* pResult)
    { (void)msg; (void)msglen; (void)iv; (void)ivlen; (void)pResult; return 0; }

/* ---- HKDF secure key-ladder (hal_hkdf.h) ---- */
static inline hal_status_t hal_hkdf_hmac_sha256_secure_init(const u8 crypto_sel)
    { (void)crypto_sel; return HAL_OK; }
static inline hal_status_t hal_hkdf_extract_secure_all(const u8 sk_idx,
        const u8 wb_idx, const u8* msg_buf)
    { (void)sk_idx; (void)wb_idx; (void)msg_buf; return HAL_OK; }
static inline hal_status_t hal_hkdf_expand_secure_all(const u8 sk_idx,
        const u8 wb_idx, const u8* nonce)
    { (void)sk_idx; (void)wb_idx; (void)nonce; return HAL_OK; }

#endif /* WOLFSSL_AMEBAPRO2_HOST_TEST */

#endif /* _WOLFPORT_AMEBAPRO2_SHIM_H_ */
