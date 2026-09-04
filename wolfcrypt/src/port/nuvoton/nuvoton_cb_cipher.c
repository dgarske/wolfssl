/* nuvoton_cb_cipher.c
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

/* AES on the M2354 CRPT engine: ECB, CBC and CTR.
 *
 * The key comes from aes->devKey, which wc_AesSetKey fills for any Aes built
 * with a crypto callback device id, and the chaining state from aes->reg. The
 * engine returns the value it would feed AES_IV for the next block in
 * AES_FDBCK, so the hardware layer writes that straight back into aes->reg and
 * a later software call picks up the stream where this one left off.
 *
 * GCM and CCM are declined for now. The engine does both, but not as a plain
 * DMA round: they need the message laid out in the GCM packet format the TRM
 * describes and a feedback buffer at AES_FBADDR, which is a further 1000 lines
 * in Nuvoton's own mbedTLS layer and cannot be checked without the part in
 * front of you. Declining means AES-GCM runs in software rather than producing
 * a tag nobody has verified. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_CIPHER) && \
    defined(WOLF_CRYPTO_CB) && !defined(NO_AES)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef WOLFSSL_NUVOTON_KS
    #include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h>
#endif

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

/* Fill in the parts of a request that every mode shares. Returns 0 when the
 * engine can take it. */
static int wc_NuvotonAesSetup(wc_NuvotonAesReq* req, Aes* aes, byte* out,
    const byte* in, word32 sz, int mode, int enc)
{
    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    /* The engine works in whole blocks. A partial tail is the caller's, and
     * for CTR it is also the case wolfCrypt tracks in aes->left. */
    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (aes->keylen != 16 && aes->keylen != 24 && aes->keylen != 32) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    XMEMSET(req, 0, sizeof(*req));
    req->in      = in;
    req->out     = out;
    req->sz      = sz;
    req->keySz   = (word32)aes->keylen;
    req->mode    = mode;
    req->encrypt = enc;
    req->keySlot = WC_NUVOTON_NO_SLOT;

#ifdef WOLFSSL_NUVOTON_KS
    /* A Key Store handle in devCtx means the engine fetches the key itself
     * and no key material passes through here. */
    if (aes->devCtx != NULL) {
        wc_NuvotonKsKey* ksKey = (wc_NuvotonKsKey*)aes->devCtx;

        req->keyMem  = ksKey->mem;
        req->keySlot = ksKey->slot;
    }
    else
#endif
    {
        req->key = (const byte*)aes->devKey;
    }

    if (mode != WC_NUVOTON_AES_ECB) {
        req->iv = (byte*)aes->reg;
    }

    return 0;
}

/* Anything the engine reports as "cannot take this one" becomes a decline, so
 * the operation runs in software instead of failing. */
static int wc_NuvotonAesRun(wc_NuvotonAesReq* req)
{
    int ret = wc_nuvoton_hw_aes(req);

    if (ret == WC_NO_ERR_TRACE(BAD_LENGTH_E) ||
        ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return ret;
}

int wc_NuvotonCb_Cipher(wc_CryptoInfo* info)
{
    wc_NuvotonAesReq req;
    int              ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->cipher.type) {
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            ret = wc_NuvotonAesSetup(&req, info->cipher.aescbc.aes,
                info->cipher.aescbc.out, info->cipher.aescbc.in,
                info->cipher.aescbc.sz, WC_NUVOTON_AES_CBC, info->cipher.enc);
            if (ret != 0) {
                return ret;
            }
            return wc_NuvotonAesRun(&req);
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            /* CTR is a stream cipher to wolfCrypt: aes->left counts the bytes
             * of the current key stream block it has not handed out yet. The
             * engine has no way to be told to start part way into a block, so
             * offload only a call that begins on a block boundary. */
            if (info->cipher.aesctr.aes != NULL &&
                info->cipher.aesctr.aes->left != 0) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
            ret = wc_NuvotonAesSetup(&req, info->cipher.aesctr.aes,
                info->cipher.aesctr.out, info->cipher.aesctr.in,
                info->cipher.aesctr.sz, WC_NUVOTON_AES_CTR, 1);
            if (ret != 0) {
                return ret;
            }
            return wc_NuvotonAesRun(&req);
#endif
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
        case WC_CIPHER_AES_ECB:
            ret = wc_NuvotonAesSetup(&req, info->cipher.aesecb.aes,
                info->cipher.aesecb.out, info->cipher.aesecb.in,
                info->cipher.aesecb.sz, WC_NUVOTON_AES_ECB, info->cipher.enc);
            if (ret != 0) {
                return ret;
            }
            return wc_NuvotonAesRun(&req);
#endif
        default:
            break;
    }

    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_CIPHER && WOLF_CRYPTO_CB &&
        * !NO_AES */
