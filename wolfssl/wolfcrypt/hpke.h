/* hpke.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file wolfssl/wolfcrypt/hpke.h
*/

#ifdef __cplusplus
    extern "C" {
#endif

/* KEM enum */
enum {
    DHKEM_P256_HKDF_SHA256 = 0x0010,
    DHKEM_P384_HKDF_SHA384 = 0x0011,
    DHKEM_P521_HKDF_SHA512 = 0x0012,
    DHKEM_X25519_HKDF_SHA256 = 0x0020,
    DHKEM_X448_HKDF_SHA512 = 0x0021,
};

/* KDF enum */
enum {
    HKDF_SHA256 = 0x0001,
    HKDF_SHA384 = 0x0002,
    HKDF_SHA512 = 0x0003,
};

/* AEAD enum */
enum {
    HPKE_AES_128_GCM = 0x0001,
    HPKE_AES_256_GCM = 0x0002,
};

typedef struct {
    int kem;
    int kdf;
    int aead;
    int Nh;
    int Nk;
    int Nn;
    int Nt;
    int Ndh;
    int Npk;
    int Nsecret;
    uint8_t kem_suite_id[5];
    uint8_t hpke_suite_id[10];
    ecc_key receiver_key[1];
    bool receiver_key_set;
    int kdf_digest;
    int curve_id;
} Hpke;

typedef struct {
    int seq;
    uint8_t key[32]; /* TODO: Use const/enum/define for these */
    uint8_t base_nonce[12];
    uint8_t exporter_secret[64];
} HpkeBaseContext;

WOLFSSL_API int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap);
WOLFSSL_API int wc_HpkeGenerateKeyPair(Hpke* hpke, ecc_key* keypair);
WOLFSSL_API int wc_HpkeSerializePublicKey(ecc_key* key, uint8_t* out);
WOLFSSL_API int wc_HpkeDeserializePublicKey(Hpke* hpke, ecc_key* key, uint8_t* in);
WOLFSSL_API int wc_HpkeSealBase(Hpke* hpke, uint8_t* info, uint32_t info_len,
    uint8_t* aad, uint32_t aad_len, uint8_t* plaintext, uint32_t pt_len, uint8_t* out);
WOLFSSL_API int wc_HpkeOpenBase(Hpke* hpke, uint8_t* enc,
    uint8_t* info, uint32_t info_len, uint8_t* aad, uint32_t aad_len,
    uint8_t* ciphertext, uint32_t ct_len, uint8_t* plaintext);

#ifdef __cplusplus
    }    /* extern "C" */
#endif
