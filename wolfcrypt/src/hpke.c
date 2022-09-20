/* hpke.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/aes.h>

static void I2OSP(int n, int w, uint8_t* out)
{
    int i;
    const int exp = 256;

    if (w <= 0) {
        return -1;
    }

    for (i = 0; i < w; i++) {
        exp *= 256;
    }

    if (n >= exp) {
        return -1;
    }

    for (i = 0; i < w && n > 0; i++) {
        out[w - ( i + 1 )] = n % 256;
        n = n >> 8;
    }
}

int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap)
{
    /* TODO: Add argument NULL checking for public API's */

    hpke->kem = kem;
    hpke->kdf = kdf;
    hpke->aead = aead;

    XMEMCPY( hpke->kem_suite_id, "KEM", strlen( "KEM" ) );
    I2OSP( kem, 2, hpke->kem_suite_id + strlen( "KEM" ) );
    XMEMCPY( hpke->hpke_suite_id, "HPKE", strlen( "HPKE" ) );
    I2OSP( kem, 2, hpke->hpke_suite_id + strlen( "HPKE" ) );
    I2OSP( kdf, 2, hpke->hpke_suite_id + strlen( "HPKE" ) + 2  );
    I2OSP( aead, 2, hpke->hpke_suite_id + strlen( "HPKE" ) + 2 + 2  );

    switch (kem) {
    case DHKEM_P256_HKDF_SHA256:
        hpke->Nsecret = 32;
        hpke->Nh = 32;
        hpke->Ndh = 32;
        hpke->Npk = 65;
        hpke->curve_id = ECC_SECP256R1;
        break;

    case DHKEM_P384_HKDF_SHA384:
        hpke->Nsecret = 48;
        hpke->Nh = 48;
        hpke->Ndh = 48;
        hpke->Npk = 97;
        hpke->curve_id = ECC_SECP384R1;
        break;

    case DHKEM_P521_HKDF_SHA512:
        hpke->Nsecret = 64;
        hpke->Nh = 64;
        hpke->Ndh = 66;
        hpke->Npk = 133;
        hpke->curve_id = ECC_SECP521R1;
        break;

    case DHKEM_X25519_HKDF_SHA256:
        hpke->Nsecret = 32;
        hpke->Nh = 32;
        hpke->Ndh = 32;
        hpke->Npk = 32;
        hpke->curve_id = ECC_X25519;
        break;

    case DHKEM_X448_HKDF_SHA512:
        hpke->Nsecret = 64;
        hpke->Nh = 64;
        hpke->Ndh = 64;
        hpke->Npk = 56;
        hpke->curve_id = ECC_X448;
        break;

    default:
        break;
    }

    switch (kdf) {
    case HKDF_SHA256:
        hpke->kdf_digest = WC_SHA256;
        break;

    case HKDF_SHA384:
        hpke->kdf_digest = WC_SHA384;
        break;

    case HKDF_SHA512:
        hpke->kdf_digest = WC_SHA512;
        break;

    default:
        break;
    }

    switch (aead) {
    case HPKE_AES_128_GCM:
        hpke->Nk = 16;
        hpke->Nn = 12;
        hpke->Nt = 16;
        break;

    case HPKE_AES_256_GCM:
        hpke->Nk = 32;
        hpke->Nn = 12;
        hpke->Nt = 16;
        break;

    default:
        break;
    }

    return 0;
}

int wc_HpkeSerializePublicKey(ecc_key* key, uint8_t* out)
{
    int ret;
    uint32_t qxLen;
    uint32_t qyLen;

    /* first byte indicates uncompressed public key */
    out[0] = 0x04;
    qxLen = qyLen = key->dp->size;

    ret = wc_ecc_export_public_raw( key, out + 1, &qxLen, out + 1 + qxLen, &qyLen );

    return ret;
}

int wc_HpkeDeserializePublicKey(Hpke* hpke, ecc_key* key, uint8_t* in)
{
    int ret;

    ret = wc_ecc_init( key );

    /* import +1 to skip the leading x.963 byte */
    if (ret == 0) {
        ret = wc_ecc_import_unsigned( key, in + 1, in + 1 + hpke->Npk / 2, NULL, hpke->curve_id );
        //ret = wc_ecc_import_raw_ex( key, in + 1, in + 1 + hpke->Npk / 2, NULL, hpke->curve_id );
    }

    return ret;
}

int wc_HpkeGenerateKeyPair( Hpke* hpke, ecc_key* keypair )
{
    int ret;
    int ecc_curve_id;
    WC_RNG rng[1];

    ret = wc_InitRng(rng);
    if (ret != 0)
        return ret;

    ret = wc_ecc_init(keypair);
    if (ret == 0) {
    switch (hpke->kem) {
        case DHKEM_P256_HKDF_SHA256:
            ret = wc_ecc_make_key_ex( rng, 32, keypair, ECC_SECP256R1 );
            break;
        case DHKEM_P384_HKDF_SHA384:
            ret = wc_ecc_make_key_ex( rng, 48, keypair, ECC_SECP384R1 );
            break;
        case DHKEM_P521_HKDF_SHA512:
            ret = wc_ecc_make_key_ex( rng, 66, keypair, ECC_SECP521R1 );
            break;
        case DHKEM_X25519_HKDF_SHA256:
            /* TODO: Add X25519 */
            break;
        case DHKEM_X448_HKDF_SHA512:
            /* TODO: Add X448 */
            break;
        default:
            ret = -1;
            break;
    }

    wc_FreeRng(rng);

    return ret;
}

int wc_HpkeLabeledExtract(Hpke* hpke, uint8_t* suite_id, uint32_t suite_id_len,
    uint8_t* salt, uint32_t salt_len, uint8_t* label, uint32_t label_len,
    uint8_t* ikm, uint32_t ikm_len, uint8_t* out )
{
    int ret;
    /* TODO: Add support for WOLFSSL_SMALL_STACK */
    uint8_t labeled_ikm[512];
    uint8_t* labeled_ikm_p;

    /* concat the labeled_ikm */
    /* version */
    /* TODO: Make all of the duplicated strings either static const char* or defines */
    XMEMCPY( labeled_ikm, "HPKE-v1", strlen( "HPKE-v1" ) );
    labeled_ikm_p = labeled_ikm + strlen( "HPKE-v1" );

    // suite_id
    /* TODO: Convert all // to /* */
    XMEMCPY( labeled_ikm_p, suite_id, suite_id_len );
    labeled_ikm_p += suite_id_len;

    // label
    /* TODO: Eliminate extra spaces around () */
    XMEMCPY( labeled_ikm_p, label, label_len );
    labeled_ikm_p += label_len;

    // ikm
    XMEMCPY( labeled_ikm_p, ikm, ikm_len );
    labeled_ikm_p += ikm_len;

    // call extract
    ret = wc_HKDF_Extract( hpke->kdf_digest, salt, salt_len, labeled_ikm, labeled_ikm_p - labeled_ikm, out );

    return ret;
}

int wc_HpkeLabeledExpand( Hpke* hpke, uint8_t* suite_id, uint32_t suite_id_len, uint8_t* prk, uint32_t prk_len, uint8_t* label, uint32_t label_len, uint8_t* info, uint32_t info_len, uint32_t L, uint8_t* out )
{
    int ret;
    // TODO I don't think it's possible to know in advance how long this should be since any label can be used
    uint8_t labeled_info[512] = { 0 };
    uint8_t* labeled_info_p;

    // copy length
    I2OSP( L, 2, labeled_info );
    labeled_info_p = labeled_info + 2;

    // version
    XMEMCPY( labeled_info_p, "HPKE-v1", strlen( "HPKE-v1" ) );
    labeled_info_p += strlen( "HPKE-v1" );

    // suite_id
    XMEMCPY( labeled_info_p, suite_id, suite_id_len );
    labeled_info_p += suite_id_len;

    // label
    XMEMCPY( labeled_info_p, label, label_len );
    labeled_info_p += label_len;

    // info
    XMEMCPY( labeled_info_p, info, info_len );
    labeled_info_p += info_len;

    // call expand
    ret = wc_HKDF_Expand( hpke->kdf_digest, prk, prk_len, labeled_info, labeled_info_p - labeled_info, out, L );

    return ret;
}

void wc_HpkeContextComputeNonce( Hpke* hpke, HpkeBaseContext* context, uint8_t* out )
{
  int i;
  uint8_t seq_bytes[12];

  // convert the sequence into a byte string with the same length as the nonce
  I2OSP( context->seq, hpke->Nn, seq_bytes );

  for ( i = 0; i < hpke->Nn; i++ )
  {
    out[i] = context->base_nonce[i] ^ seq_bytes[i];
  }
}

int wc_HpkeExtractAndExpand( Hpke* hpke, uint8_t* dh, uint32_t dh_len, uint8_t* kem_context, uint32_t kem_context_length, uint8_t* shared_secret )
{
    int ret;
    // max length is the largest hmac digest possible
    uint8_t eae_prk[WC_MAX_DIGEST_SIZE];

    // extract
    ret = wc_HpkeLabeledExtract( hpke, hpke->kem_suite_id, sizeof( hpke->kem_suite_id ), NULL, 0, (uint8_t*)"eae_prk", strlen( "eae_prk" ), dh, dh_len, eae_prk );

    // expand
    /* TODO: Max line length is 80 */
    if ( ret == 0 ) {
        ret = wc_HpkeLabeledExpand( hpke, hpke->kem_suite_id, sizeof( hpke->kem_suite_id ), eae_prk, hpke->Nh, "shared_secret", strlen( "shared_secret" ), kem_context, kem_context_length, hpke->Nsecret, shared_secret );
    }

    return ret;
}

int wc_HpkeKeyScheduleBase( Hpke* hpke, HpkeBaseContext* context, uint8_t* shared_secret, uint8_t* info, uint32_t info_len )
{
    int ret;
    // 1 for mode and WC_MAX_DIGEST_SIZE times 2 for psk_id_hash and info_hash
    uint8_t key_schedule_context[1 + 2 * WC_MAX_DIGEST_SIZE];
    // maximum size of secret is largest hash of extract
    uint8_t secret[WC_MAX_DIGEST_SIZE];

    // set the sequence to 0
    context->seq = 0;

    // 0 for mode
    key_schedule_context[0] = 0;

    // extract psk_id, which for base is null
    ret = wc_HpkeLabeledExtract( hpke, hpke->hpke_suite_id, sizeof( hpke->hpke_suite_id ), NULL, 0, "psk_id_hash", strlen( "psk_id_hash" ), NULL, 0, key_schedule_context + 1 );

    // extract info
    if ( ret == 0 )
    ret = wc_HpkeLabeledExtract( hpke, hpke->hpke_suite_id, sizeof( hpke->hpke_suite_id ), NULL, 0, "info_hash", strlen( "info_hash" ), info, info_len, key_schedule_context + 1 + hpke->Nh );

    // extract secret
    if ( ret == 0 )
    ret = wc_HpkeLabeledExtract( hpke, hpke->hpke_suite_id, sizeof( hpke->hpke_suite_id ), shared_secret, hpke->Nsecret, "secret", strlen( "secret" ), NULL, 0, secret );

    // expand key
    if ( ret == 0 )
    ret = wc_HpkeLabeledExpand( hpke, hpke->hpke_suite_id, sizeof( hpke->hpke_suite_id ), secret, hpke->Nh, "key", strlen( "key" ), key_schedule_context, 1 + 2 * hpke->Nh, hpke->Nk, context->key );

    // expand nonce
    if ( ret == 0 )
    ret = wc_HpkeLabeledExpand( hpke, hpke->hpke_suite_id, sizeof( hpke->hpke_suite_id ), secret, hpke->Nh, "base_nonce", strlen( "base_nonce" ), key_schedule_context, 1 + 2 * hpke->Nh, hpke->Nn, context->base_nonce );

    // expand exporter_secret
    if ( ret == 0 )
    ret = wc_HpkeLabeledExpand( hpke, hpke->hpke_suite_id, sizeof( hpke->hpke_suite_id ), secret, hpke->Nh, "exp", strlen( "exp" ), key_schedule_context, 1 + 2 * hpke->Nh, hpke->Nh, context->exporter_secret );

    return ret;
}

int wc_HpkeEncap( Hpke* hpke, uint8_t* shared_secret, uint8_t* enc )
{
    int ret;
    ecc_key ephemiral_key[1];
    // maximum value of Ndh is 66
    uint8_t dh[66];
    uint32_t dh_len = hpke->Ndh;
    // kem_context max is 133 for pubkey max size * 2 for ephemiral_key and receiver_key
    uint8_t kem_context[266];

    // generate keypair
    ret = wc_HpkeGenerateKeyPair( hpke, ephemiral_key );

    if ( ret != 0 )
        return ret;

    // generate dh
    if ( ret == 0 )
    {
        ephemiral_key->rng = wc_rng_new( NULL, 0, NULL );

        ret = wc_ecc_shared_secret( ephemiral_key, hpke->receiver_key, dh, &dh_len );

        wc_rng_free( ephemiral_key->rng );
    }

    // serialize ephemiral_key
    if ( ret == 0 )
        ret = wc_HpkeSerializePublicKey( ephemiral_key, enc );

    // free ephemiral_key
    wc_ecc_free( ephemiral_key );

    if ( ret == 0 )
    {
        // copy enc into kem_context
        XMEMCPY( kem_context, enc, hpke->Npk );

        // serialize pkR into kem_context
        ret = wc_HpkeSerializePublicKey( hpke->receiver_key, kem_context + hpke->Npk );
    }

    // compute the shared secret
    if ( ret == 0 )
        ret = wc_HpkeExtractAndExpand( hpke, dh, dh_len, kem_context, hpke->Npk * 2, shared_secret );

    return ret;
}

int wc_HpkeSetupBaseSender( Hpke* hpke, HpkeBaseContext* context, uint8_t* info, uint32_t info_len, uint8_t* enc )
{
    int ret;
    // 64 is the maximum size of Nsecret
    uint8_t shared_secret[64];

    // encap
    ret = wc_HpkeEncap( hpke, shared_secret, enc );

    // schedule
    if ( ret == 0 )
        ret = wc_HpkeKeyScheduleBase( hpke, context, shared_secret, info, info_len );

    return ret;
}

int wc_HpkeContextSealBase( Hpke* hpke, HpkeBaseContext* context, uint8_t* aad, uint32_t aad_len, uint8_t* plaintext, uint32_t pt_len, uint8_t* out )
{
    int ret;
    uint8_t nonce[12];
    Aes aes_key[1];

    wc_HpkeContextComputeNonce( hpke, context, nonce );

    // TODO implement chacha and change this based on the alg
    ret = wc_AesGcmSetKey( aes_key, context->key, hpke->Nk );

    if ( ret == 0 )
        ret = wc_AesGcmEncrypt( aes_key, out, plaintext, pt_len, nonce, hpke->Nn, out + pt_len, hpke->Nt, aad, aad_len );

    if ( ret == 0 )
        context->seq++;

    return ret;
}

int wc_HpkeSealBase( Hpke* hpke, uint8_t* info, uint32_t info_len, uint8_t* aad, uint32_t aad_len, uint8_t* plaintext, uint32_t pt_len, uint8_t* ciphertext, uint8_t* enc )
{
    int ret;
    HpkeBaseContext context[1];

    if ( hpke->receiver_key_set == false )
    {
        return -1;
    }

    // setup the context and enc
    ret = wc_HpkeSetupBaseSender( hpke, context, info, info_len, enc );

    // run seal using the context
    if ( ret == 0 )
        ret = wc_HpkeContextSealBase( hpke, context, aad, aad_len, plaintext, pt_len, ciphertext );

    return ret;
}

int wc_HpkeDecap( Hpke* hpke, uint8_t* enc, uint8_t* shared_secret )
{
    int ret;
    // maximum value of Ndh is 66
    uint8_t dh[66];
    uint32_t dh_len = hpke->Ndh;
    uint8_t kem_context[266];
    ecc_key ephemiral_key[1];

    // deserialize ephemiral_key from enc
    ret = wc_HpkeDeserializePublicKey( hpke, ephemiral_key, enc );

    // generate dh
    if ( ret == 0 )
    {
        hpke->receiver_key->rng = wc_rng_new( NULL, 0, NULL );

        ret = wc_ecc_shared_secret( hpke->receiver_key, ephemiral_key, dh, &dh_len );

        wc_rng_free( hpke->receiver_key->rng );
    }

    if ( ret == 0 )
    {
        // copy enc into kem_context
        XMEMCPY( kem_context, enc, hpke->Npk );

        // serialize pkR into kem_context
        ret = wc_HpkeSerializePublicKey( hpke->receiver_key, kem_context + hpke->Npk );
    }

    // compute the shared secret
    if ( ret == 0 )
        ret = wc_HpkeExtractAndExpand( hpke, dh, dh_len, kem_context, hpke->Npk * 2, shared_secret );

    return ret;
}

int wc_HpkeSetupBaseReceiver( Hpke* hpke, HpkeBaseContext* context, uint8_t* enc, uint8_t* info, uint32_t info_len )
{
    int ret;
    // 64 is the maximum size of Nsecret
    uint8_t shared_secret[64];

    // decap
    ret = wc_HpkeDecap( hpke, enc, shared_secret );

    // schedule
    if ( ret == 0 )
        ret = wc_HpkeKeyScheduleBase( hpke, context, shared_secret, info, info_len );

    return ret;
}

int wc_HpkeContextOpenBase( Hpke* hpke, HpkeBaseContext* context, uint8_t* aad, uint32_t aad_len, uint8_t* ciphertext, uint32_t ct_len, uint8_t* out )
{
    int ret;
    uint8_t nonce[12];
    Aes aes_key[1];

    wc_HpkeContextComputeNonce( hpke, context, nonce );

    // TODO implement chacha and change this based on the alg
    ret = wc_AesGcmSetKey( aes_key, context->key, hpke->Nk );

    if ( ret == 0 )
        ret = wc_AesGcmDecrypt( aes_key, out, ciphertext, ct_len, nonce, hpke->Nn, ciphertext + ct_len, hpke->Nt, aad, aad_len );

    if ( ret == 0 )
        context->seq++;

    return ret;
}

int wc_HpkeOpenBase( Hpke* hpke, uint8_t* enc, uint8_t* info, uint32_t info_len, uint8_t* aad, uint32_t aad_len, uint8_t* ciphertext, uint32_t ct_len, uint8_t* plaintext )
{
    int ret;
    HpkeBaseContext context[1];

    // setup receiver
    ret = wc_HpkeSetupBaseReceiver( hpke, context, enc, info, info_len );

    // open the ciphertext
    if ( ret == 0 )
        ret = wc_HpkeContextOpenBase( hpke, context, aad, aad_len, ciphertext, ct_len, plaintext );

    return ret;
}
