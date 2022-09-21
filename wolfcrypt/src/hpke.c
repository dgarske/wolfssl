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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hpke.h>

static const char* KEM_STR = "KEM";
static const int KEM_STR_LEN = 3;

static const char* HPKE_STR = "HPKE";
static const int HPKE_STR_LEN = 4;

static const char* HPKE_VERSION_STR = "HPKE-v1";
static const int HPKE_VERSION_STR_LEN = 7;

static const char* EAE_PRK_LABEL_STR = "eae_prk";
static const int EAE_PRK_LABEL_STR_LEN = 7;

static const char* SHARED_SECRET_LABEL_STR = "shared_secret";
static const int SHARED_SECRET_LABEL_STR_LEN = 13;

static const char* PSK_ID_HASH_LABEL_STR = "psk_id_hash";
static const int PSK_ID_HASH_LABEL_STR_LEN = 11;

static const char* INFO_HASH_LABEL_STR = "info_hash";
static const int INFO_HASH_LABEL_STR_LEN = 9;

static const char* SECRET_LABEL_STR = "secret";
static const int SECRET_LABEL_STR_LEN = 6;

static const char* KEY_LABEL_STR = "key";
static const int KEY_LABEL_STR_LEN = 3;

static const char* BASE_NONCE_LABEL_STR = "base_nonce";
static const int BASE_NONCE_LABEL_STR_LEN = 10;

static const char* EXP_LABEL_STR = "exp";
static const int EXP_LABEL_STR_LEN = 3;

static int I2OSP(int n, int w, byte* out)
{
    int i;

    if (w <= 0 || w > 32)
    {
        return MP_VAL;
    }

    // make sure the byte string is cleared
    XMEMSET( out, 0, w );

    // we're only concerned with up to integer max
    if ((n > 256 && w < 2) ||
        (n > 65536 && w < 3) ||
        (n > 16777216 && w < 4))
    {
        return MP_VAL;
    }

    for (i = 0; i < w && n > 0; i++)
    {
        out[w - ( i + 1 )] = n % 256;
        n = n >> 8;
    }

    return 0;
}

int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap)
{
    int ret;

    if (hpke == NULL || kem == 0 || kdf == 0 || aead == 0)
    {
      return BAD_FUNC_ARG;
    }

    hpke->kem = kem;
    hpke->kdf = kdf;
    hpke->aead = aead;
    hpke->heap = heap;

    XMEMCPY(hpke->kem_suite_id, KEM_STR, KEM_STR_LEN);

    ret = I2OSP(kem, 2, hpke->kem_suite_id + KEM_STR_LEN);

    XMEMCPY(hpke->hpke_suite_id, HPKE_STR, HPKE_STR_LEN);

    if (ret == 0)
      ret = I2OSP(kem, 2, hpke->hpke_suite_id + HPKE_STR_LEN);

    if (ret == 0)
      ret = I2OSP(kdf, 2, hpke->hpke_suite_id + HPKE_STR_LEN + 2);

    if (ret == 0)
      ret = I2OSP(aead, 2, hpke->hpke_suite_id + HPKE_STR_LEN + 2 + 2);

    if (ret != 0)
      return ret;

    switch (kem)
    {
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
            //hpke->curve_id = ECC_X25519;
            break;

        case DHKEM_X448_HKDF_SHA512:
            hpke->Nsecret = 64;
            hpke->Nh = 64;
            hpke->Ndh = 64;
            hpke->Npk = 56;
            //hpke->curve_id = ECC_X448;
            break;

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    switch (kdf)
    {
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
            ret = BAD_FUNC_ARG;
            break;
    }

    switch (aead)
    {
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
            ret = BAD_FUNC_ARG;
            break;
    }

    return 0;
}

int wc_HpkeSerializePublicKey(ecc_key* key, byte* out)
{
    int ret;
    word32 qxLen;
    word32 qyLen;

    if (key == NULL || out == NULL)
      return BAD_FUNC_ARG;

    /* first byte indicates uncompressed public key */
    out[0] = 0x04;
    qxLen = qyLen = key->dp->size;

    ret = wc_ecc_export_public_raw(key, out + 1, &qxLen, out + 1 + qxLen,
        &qyLen);

    return ret;
}

int wc_HpkeDeserializePublicKey(Hpke* hpke, ecc_key* key, byte* in)
{
    int ret;

    if (hpke == NULL || key == NULL || in == NULL)
      return BAD_FUNC_ARG;

    ret = wc_ecc_init(key);

    /* import +1 to skip the leading x.963 byte */
    if (ret == 0)
        ret = wc_ecc_import_unsigned(key, in + 1, in + 1 + hpke->Npk / 2, NULL,
            hpke->curve_id);
        /*
        ret = wc_ecc_import_raw_ex(key, (char*)in + 1, (char*)in + 1 + hpke->Npk / 2, NULL,
            hpke->curve_id);
        */

    return ret;
}

int wc_HpkeGenerateKeyPair( Hpke* hpke, ecc_key* keypair )
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* rng;
#else
    WC_RNG rng[1];
#endif

    if (hpke == NULL || keypair == NULL)
      return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    // allocate after we know hpke is good
    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), hpke->heap, DYNAMIC_TYPE_RNG);
#endif

    ret = wc_InitRng(rng);

    if (ret == 0)
      ret = wc_ecc_init(keypair);

    if (ret == 0)
        switch (hpke->kem)
        {
            case DHKEM_P256_HKDF_SHA256:
                ret = wc_ecc_make_key_ex(rng, 32, keypair, ECC_SECP256R1);
                break;
            case DHKEM_P384_HKDF_SHA384:
                ret = wc_ecc_make_key_ex(rng, 48, keypair, ECC_SECP384R1);
                break;
            case DHKEM_P521_HKDF_SHA512:
                ret = wc_ecc_make_key_ex(rng, 66, keypair, ECC_SECP521R1);
                break;
            case DHKEM_X25519_HKDF_SHA256:
                /* TODO: Add X25519 */
                break;
            case DHKEM_X448_HKDF_SHA512:
                /* TODO: Add X448 */
                break;
            default:
                ret = BAD_FUNC_ARG;
                break;
        }

    wc_FreeRng(rng);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(rng, hpke->heap, DYNAMIC_TYPE_RNG);
#endif

    return ret;
}

static int wc_HpkeLabeledExtract(Hpke* hpke, byte* suite_id, word32 suite_id_len,
    byte* salt, word32 salt_len, byte* label, word32 label_len,
    byte* ikm, word32 ikm_len, byte* out)
{
    int ret;
    byte* labeled_ikm_p;
#ifdef WOLFSSL_SMALL_STACK
    byte* labeled_ikm = XMALLOC(sizeof(byte) * 512, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    byte labeled_ikm[512];
#endif

    /* concat the labeled_ikm */
    /* version */
    XMEMCPY(labeled_ikm, HPKE_VERSION_STR, HPKE_VERSION_STR_LEN);
    labeled_ikm_p = labeled_ikm + HPKE_VERSION_STR_LEN;

    /* suite_id */
    XMEMCPY(labeled_ikm_p, suite_id, suite_id_len);
    labeled_ikm_p += suite_id_len;

    /* label */
    XMEMCPY(labeled_ikm_p, label, label_len);
    labeled_ikm_p += label_len;

    /* ikm */
    XMEMCPY(labeled_ikm_p, ikm, ikm_len);
    labeled_ikm_p += ikm_len;

    /* call extract */
    ret = wc_HKDF_Extract(hpke->kdf_digest, salt, salt_len, labeled_ikm,
        labeled_ikm_p - labeled_ikm, out);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(labeled_ikm, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeLabeledExpand(Hpke* hpke, byte* suite_id, word32 suite_id_len,
    byte* prk, word32 prk_len, byte* label, word32 label_len, byte* info,
    word32 info_len, word32 L, byte* out)
{
    int ret;
    byte* labeled_info_p;
#ifdef WOLFSSL_SMALL_STACK
    byte* labeled_info = XMALLOC(sizeof(byte) * 512, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    byte labeled_info[512];
#endif

    /* copy length */
    ret = I2OSP(L, 2, labeled_info);
    labeled_info_p = labeled_info + 2;

    if (ret == 0)
    {
        /* version */
        XMEMCPY(labeled_info_p, HPKE_VERSION_STR, HPKE_VERSION_STR_LEN);
        labeled_info_p += HPKE_VERSION_STR_LEN;

        /* suite_id */
        XMEMCPY(labeled_info_p, suite_id, suite_id_len);
        labeled_info_p += suite_id_len;

        /* label */
        XMEMCPY(labeled_info_p, label, label_len);
        labeled_info_p += label_len;

        /* info */
        XMEMCPY(labeled_info_p, info, info_len);
        labeled_info_p += info_len;

        /* call expand */
        ret = wc_HKDF_Expand(hpke->kdf_digest, prk, prk_len, labeled_info,
            labeled_info_p - labeled_info, out, L);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(labeled_info, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeContextComputeNonce(Hpke* hpke, HpkeBaseContext* context, byte* out)
{
    int i;
    int ret;
    /* TODO is this small enough for small stack? */
    byte seq_bytes[HPKE_Nn_MAX];

    /* convert the sequence into a byte string with the same length as the
        nonce */
    ret = I2OSP(context->seq, hpke->Nn, seq_bytes);

    if (ret != 0)
        return ret;

    for (i = 0; i < hpke->Nn; i++)
    {
        out[i] = context->base_nonce[i] ^ seq_bytes[i];
    }

    return ret;
}

static int wc_HpkeExtractAndExpand( Hpke* hpke, byte* dh, word32 dh_len,
    byte* kem_context, word32 kem_context_length, byte* shared_secret)
{
    int ret;
    /* max length is the largest hmac digest possible */
#ifdef WOLFSSL_SMALL_STACK
    byte* eae_prk = XMALLOC(sizeof(byte) * WC_MAX_DIGEST_SIZE, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    byte eae_prk[WC_MAX_DIGEST_SIZE];
#endif

    /* extract */
    ret = wc_HpkeLabeledExtract(hpke, hpke->kem_suite_id,
        sizeof( hpke->kem_suite_id ), NULL, 0, (byte*)EAE_PRK_LABEL_STR,
        EAE_PRK_LABEL_STR_LEN, dh, dh_len, eae_prk);

    /* expand */
    if ( ret == 0 )
        ret = wc_HpkeLabeledExpand(hpke, hpke->kem_suite_id,
            sizeof( hpke->kem_suite_id ), eae_prk, hpke->Nh,
            (byte*)SHARED_SECRET_LABEL_STR, SHARED_SECRET_LABEL_STR_LEN,
            kem_context, kem_context_length, hpke->Nsecret, shared_secret);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(eae_prk, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeKeyScheduleBase(Hpke* hpke, HpkeBaseContext* context,
    byte* shared_secret, byte* info, word32 info_len)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    byte* key_schedule_context =
        XMALLOC(sizeof(byte) * (1 + 2 * WC_MAX_DIGEST_SIZE), hpke->heap,
        DYNAMIC_TYPE_NONE);
    byte* secret = XMALLOC(sizeof(byte) * WC_MAX_DIGEST_SIZE, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    /* 1 for mode and WC_MAX_DIGEST_SIZE times 2 for psk_id_hash and info_hash */
    byte key_schedule_context[1 + 2 * WC_MAX_DIGEST_SIZE];
    /* maximum size of secret is largest hash of extract */
    byte secret[WC_MAX_DIGEST_SIZE];
#endif

    /* set the sequence to 0 */
    context->seq = 0;

    /* 0 for mode */
    key_schedule_context[0] = 0;

    /* extract psk_id, which for base is null */
    ret = wc_HpkeLabeledExtract(hpke, hpke->hpke_suite_id,
        sizeof( hpke->hpke_suite_id ), NULL, 0, (byte*)PSK_ID_HASH_LABEL_STR,
        PSK_ID_HASH_LABEL_STR_LEN, NULL, 0, key_schedule_context + 1);

    /* extract info */
    if (ret == 0)
        ret = wc_HpkeLabeledExtract(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), NULL, 0, (byte*)INFO_HASH_LABEL_STR,
            INFO_HASH_LABEL_STR_LEN, info, info_len,
            key_schedule_context + 1 + hpke->Nh);

    /* extract secret */
    if (ret == 0)
        ret = wc_HpkeLabeledExtract(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), shared_secret, hpke->Nsecret,
            (byte*)SECRET_LABEL_STR, SECRET_LABEL_STR_LEN, NULL, 0, secret);

    /* expand key */
    if (ret == 0)
        ret = wc_HpkeLabeledExpand(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), secret, hpke->Nh,
            (byte*)KEY_LABEL_STR, KEY_LABEL_STR_LEN, key_schedule_context,
            1 + 2 * hpke->Nh, hpke->Nk, context->key);

    /* expand nonce */
    if (ret == 0)
        ret = wc_HpkeLabeledExpand(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), secret, hpke->Nh,
            (byte*)BASE_NONCE_LABEL_STR, BASE_NONCE_LABEL_STR_LEN,
            key_schedule_context, 1 + 2 * hpke->Nh, hpke->Nn,
            context->base_nonce);

    /* expand exporter_secret */
    if (ret == 0)
        ret = wc_HpkeLabeledExpand(hpke, hpke->hpke_suite_id,
            sizeof( hpke->hpke_suite_id ), secret, hpke->Nh,
            (byte*)EXP_LABEL_STR, EXP_LABEL_STR_LEN, key_schedule_context,
            1 + 2 * hpke->Nh, hpke->Nh, context->exporter_secret);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(key_schedule_context, hpke->heap, DYNAMIC_TYPE_NONE);
    XFREE(secret, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeEncap(Hpke* hpke, byte* shared_secret, byte* enc)
{
    int ret;
    word32 dh_len = hpke->Ndh;
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* ephemiral_key = (ecc_key*)XMALLOC(sizeof(ecc_key), hpke->heap,
        DYNAMIC_TYPE_ECC);
    byte* dh = XMALLOC(sizeof(byte) * hpke->Ndh, hpke->heap, DYNAMIC_TYPE_NONE);
    byte* kem_context = XMALLOC(sizeof(byte) * hpke->Npk * 2, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    ecc_key ephemiral_key[1];
    byte dh[HPKE_Ndh_MAX];
    byte kem_context[HPKE_Npk_MAX * 2];
#endif

    /* generate keypair */
    ret = wc_HpkeGenerateKeyPair(hpke, ephemiral_key);

    if (ret == 0)
    {
        /* generate dh */
        ephemiral_key->rng = wc_rng_new(NULL, 0, hpke->heap);

        ret = wc_ecc_shared_secret(ephemiral_key, hpke->receiver_key, dh, &dh_len);

        wc_rng_free(ephemiral_key->rng);

        /* serialize ephemiral_key */
        if (ret == 0)
            ret = wc_HpkeSerializePublicKey(ephemiral_key, enc);

        /* free ephemiral_key */
        wc_ecc_free(ephemiral_key);
    }

    if (ret == 0)
    {
        /* copy enc into kem_context */
        XMEMCPY(kem_context, enc, hpke->Npk);

        /* serialize pkR into kem_context */
        ret = wc_HpkeSerializePublicKey(hpke->receiver_key,
            kem_context + hpke->Npk);
    }

    /* compute the shared secret */
    if (ret == 0)
        ret = wc_HpkeExtractAndExpand(hpke, dh, dh_len, kem_context,
            hpke->Npk * 2, shared_secret);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(ephemiral_key, hpke->heap, DYNAMIC_TYPE_ECC);
    XFREE(dh, hpke->heap, DYNAMIC_TYPE_NONE);
    XFREE(kem_context, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeSetupBaseSender(Hpke* hpke, HpkeBaseContext* context, byte* info,
    word32 info_len, byte* enc)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    byte* shared_secret = XMALLOC(sizeof(byte) * hpke->Nsecret, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    byte shared_secret[HPKE_Nsecret_MAX];
#endif

    /* encap */
    ret = wc_HpkeEncap(hpke, shared_secret, enc);

    /* schedule */
    if (ret == 0)
        ret = wc_HpkeKeyScheduleBase(hpke, context, shared_secret, info,
            info_len);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(shared_secret, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeContextSealBase(Hpke* hpke, HpkeBaseContext* context, byte* aad,
    word32 aad_len, byte* plaintext, word32 pt_len, byte* out)
{
    int ret;
    /* TODO is this small enough for small stack? */
    byte nonce[HPKE_Nn_MAX];
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes_key = XMALLOC(sizeof(Aes), hpke->heap, DYNAMIC_TYPE_AES);
#else
    Aes aes_key[1];
#endif

    ret = wc_HpkeContextComputeNonce(hpke, context, nonce);

    /* TODO implement chacha and change this based on the alg */
    if (ret == 0)
        ret = wc_AesGcmSetKey( aes_key, context->key, hpke->Nk );

    if (ret == 0)
        ret = wc_AesGcmEncrypt(aes_key, out, plaintext, pt_len, nonce, hpke->Nn,
            out + pt_len, hpke->Nt, aad, aad_len);

    if (ret == 0)
        context->seq++;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes_key, hpke->heap, DYNAMIC_TYPE_AES);
#endif

    return ret;
}

int wc_HpkeSealBase(Hpke* hpke, byte* info, word32 info_len, byte* aad,
    word32 aad_len, byte* plaintext, word32 pt_len, byte* ciphertext, byte* enc)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    HpkeBaseContext* context;
#else
    HpkeBaseContext context[1];
#endif

    /* check that all the buffers are non NULL or optional with 0 length */
    if (hpke == NULL || hpke->receiver_pubkey_set == 0 ||
        (info == NULL && info_len != 0) || (aad == NULL && aad_len != 0) ||
        plaintext == NULL || ciphertext == NULL || enc == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    // allocate after we know hpke is good
    context = XMALLOC(sizeof(HpkeBaseContext), hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    /* setup the context and enc */
    ret = wc_HpkeSetupBaseSender(hpke, context, info, info_len, enc);

    /* run seal using the context */
    if (ret == 0)
        ret = wc_HpkeContextSealBase(hpke, context, aad, aad_len, plaintext,
            pt_len, ciphertext);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(context, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeDecap(Hpke* hpke, byte* enc, byte* shared_secret)
{
    int ret;
    word32 dh_len = hpke->Ndh;
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* ephemiral_key = (ecc_key*)XMALLOC(sizeof(ecc_key), hpke->heap,
        DYNAMIC_TYPE_ECC);
    byte* dh = XMALLOC(sizeof(byte) * hpke->Ndh, hpke->heap, DYNAMIC_TYPE_NONE);
    byte* kem_context = XMALLOC(sizeof(byte) * hpke->Npk * 2, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    ecc_key ephemiral_key[1];
    byte dh[HPKE_Ndh_MAX];
    byte kem_context[HPKE_Npk_MAX * 2];
#endif

    /* deserialize ephemiral_key from enc */
    ret = wc_HpkeDeserializePublicKey(hpke, ephemiral_key, enc);

    if (ret == 0)
    {
        /* generate dh */
        hpke->receiver_key->rng = wc_rng_new(NULL, 0, hpke->heap);

        ret = wc_ecc_shared_secret(hpke->receiver_key, ephemiral_key, dh,
            &dh_len);

        wc_rng_free(hpke->receiver_key->rng);

        /* free ephemiral_key */
        wc_ecc_free(ephemiral_key);
    }

    if (ret == 0)
    {
        /* copy enc into kem_context */
        XMEMCPY(kem_context, enc, hpke->Npk);

        /* serialize pkR into kem_context */
        ret = wc_HpkeSerializePublicKey(hpke->receiver_key,
            kem_context + hpke->Npk);
    }

    /* compute the shared secret */
    if (ret == 0)
        ret = wc_HpkeExtractAndExpand(hpke, dh, dh_len, kem_context,
            hpke->Npk * 2, shared_secret);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(ephemiral_key, hpke->heap, DYNAMIC_TYPE_ECC);
    XFREE(dh, hpke->heap, DYNAMIC_TYPE_NONE);
    XFREE(kem_context, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeSetupBaseReceiver(Hpke* hpke, HpkeBaseContext* context,
    byte* enc, byte* info, word32 info_len)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    byte* shared_secret = XMALLOC(sizeof(byte) * hpke->Nsecret, hpke->heap,
        DYNAMIC_TYPE_NONE);
#else
    byte shared_secret[HPKE_Nsecret_MAX];
#endif

    /* decap */
    ret = wc_HpkeDecap(hpke, enc, shared_secret);

    /* schedule */
    if ( ret == 0 )
        ret = wc_HpkeKeyScheduleBase(hpke, context, shared_secret, info,
            info_len);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(shared_secret, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

static int wc_HpkeContextOpenBase(Hpke* hpke, HpkeBaseContext* context, byte* aad,
    word32 aad_len, byte* ciphertext, word32 ct_len, byte* out)
{
    int ret;
    byte nonce[HPKE_Nn_MAX];
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes_key = XMALLOC(sizeof(Aes), hpke->heap, DYNAMIC_TYPE_AES);
#else
    Aes aes_key[1];
#endif

    ret = wc_HpkeContextComputeNonce(hpke, context, nonce);

    /* TODO implement chacha and change this based on the alg */
    if (ret == 0)
        ret = wc_AesGcmSetKey(aes_key, context->key, hpke->Nk);

    if (ret == 0)
        ret = wc_AesGcmDecrypt(aes_key, out, ciphertext, ct_len, nonce,
            hpke->Nn, ciphertext + ct_len, hpke->Nt, aad, aad_len);

    if (ret == 0)
        context->seq++;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes_key, hpke->heap, DYNAMIC_TYPE_AES);
#endif

    return ret;
}

int wc_HpkeOpenBase(Hpke* hpke, byte* enc, byte* info, word32 info_len,
    byte* aad, word32 aad_len, byte* ciphertext, word32 ct_len,
    byte* plaintext)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    HpkeBaseContext* context;
#else
    HpkeBaseContext context[1];
#endif

    /* check that all the buffer are non NULL or optional with 0 length */
    if (hpke == NULL || hpke->receiver_privkey_set == 0 ||
        (info == NULL && info_len != 0) || (aad == NULL && aad_len != 0) ||
        plaintext == NULL || ciphertext == NULL || enc == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    // allocate after we know hpke is good
    context = XMALLOC(sizeof(HpkeBaseContext), hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    /* setup receiver */
    ret = wc_HpkeSetupBaseReceiver(hpke, context, enc, info, info_len);

    /* open the ciphertext */
    if ( ret == 0 )
        ret = wc_HpkeContextOpenBase(hpke, context, aad, aad_len, ciphertext,
            ct_len, plaintext);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(context, hpke->heap, DYNAMIC_TYPE_NONE);
#endif

    return ret;
}

void wc_HpkeFree(Hpke* hpke)
{
  if (hpke->receiver_privkey_set == 1 || hpke->receiver_pubkey_set == 1)
  {
      wc_ecc_free(hpke->receiver_key);
  }
}
