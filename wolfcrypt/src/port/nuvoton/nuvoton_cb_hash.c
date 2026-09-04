/* nuvoton_cb_hash.c
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

/* Hashing on the M2354 CRPT SHA engine.
 *
 * The engine can cascade a message across several DMA rounds, but it holds
 * that partial state in its own registers and offers no way to save and
 * restore it, so only one cascade can be open at a time. wolfCrypt interleaves
 * hashes freely - a TLS handshake runs the transcript hash and the record MAC
 * against each other, and wc_Sha256Copy forks the transcript - so a cascade
 * cannot be tied to a wolfCrypt hash object. Nuvoton's own mbedTLS layer has
 * the same limitation and does not guard against it.
 *
 * Each context therefore saves its message in its own buffer and hashes it all
 * in one engine call at final(), which is what the Versal Gen2 ASU port does
 * for the same reason. See wolfcrypt/src/port/xilinx/versal_gen2_asu/asu_hash.c.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_HASH) && \
    defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLFSSL_HASH_KEEP
    #error "WOLFSSL_NUVOTON_HASH requires WOLFSSL_HASH_KEEP (_wc_Hash_Grow)"
#endif

/* Per hash context message accumulation, held in the wolfSSL hash devCtx. */
typedef struct {
    byte*  msg;  /* accumulated message */
    word32 used; /* bytes accumulated */
    word32 len;  /* buffer capacity */
} NuvotonHashKeep;

/* Free a saved message. It holds the data we hashed, so wipe it first. */
static void wc_NuvotonHashKeepFree(NuvotonHashKeep* keep)
{
    if (keep == NULL) {
        return;
    }
    if (keep->msg != NULL) {
        ForceZero(keep->msg, keep->len);
        XFREE(keep->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(keep, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Size of the hash context for this type, or 0 if we do not support it. */
static word32 wc_NuvotonHashCtxSize(int hashType)
{
    switch (hashType) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            return (word32)sizeof(wc_Sha);
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            return (word32)sizeof(wc_Sha224);
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            return (word32)sizeof(wc_Sha256);
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            return (word32)sizeof(wc_Sha384);
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            return (word32)sizeof(wc_Sha512);
#endif
        default:
            return 0;
    }
}

/* Address of the devCtx field for this hash type, or NULL if unsupported. */
static void** wc_NuvotonHashDevCtx(void* hashCtx, int hashType)
{
    if (hashCtx == NULL) {
        return NULL;
    }

    switch (hashType) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            return &((wc_Sha*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            return &((wc_Sha224*)hashCtx)->devCtx;
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            return &((wc_Sha256*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            return &((wc_Sha384*)hashCtx)->devCtx;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            return &((wc_Sha512*)hashCtx)->devCtx;
#endif
        default:
            return NULL;
    }
}

/* Work out the engine mode, digest length and devCtx for this hash. Returns 0
 * if the CRPT SHA engine can do it. */
static int wc_NuvotonHashResolve(wc_CryptoInfo* info, void*** devCtx,
    int* shaMode, word32* hashLen)
{
    if (info == NULL || devCtx == NULL || shaMode == NULL || hashLen == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->hash.type) {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha1, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_1;
            *hashLen = WC_SHA_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha224, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_224;
            *hashLen = WC_SHA224_DIGEST_SIZE;
            break;
#endif
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha256, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_256;
            *hashLen = WC_SHA256_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha384, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_384;
            *hashLen = WC_SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
    #ifdef WOLFSSL_SHA512_HASHTYPE
            /* The engine only does full SHA-512. The truncated versions start
             * from different initial values, so let software handle them. */
            if (info->hash.sha512 != NULL &&
                (info->hash.sha512->hashType == WC_HASH_TYPE_SHA512_224 ||
                 info->hash.sha512->hashType == WC_HASH_TYPE_SHA512_256)) {
                return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            }
    #endif
            *devCtx  = wc_NuvotonHashDevCtx(info->hash.sha512, info->hash.type);
            *shaMode = WC_NUVOTON_SHA_512;
            *hashLen = WC_SHA512_DIGEST_SIZE;
            break;
#endif
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    if (*devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return 0;
}

/* Handles update and final for a hash. */
static int wc_NuvotonHashCompute(wc_CryptoInfo* info)
{
    void**           devCtxPtr = NULL;
    int              shaMode = 0;
    word32           hashLen = 0;
    NuvotonHashKeep* keep;
    int              ret;

    ret = wc_NuvotonHashResolve(info, &devCtxPtr, &shaMode, &hashLen);
    if (ret != 0) {
        return ret;
    }

    keep = (NuvotonHashKeep*)(*devCtxPtr);

    /* update: add this chunk to the saved message. */
    if (info->hash.in != NULL) {
        if (keep == NULL) {
            keep = (NuvotonHashKeep*)XMALLOC(sizeof(NuvotonHashKeep), NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (keep == NULL) {
                return MEMORY_E;
            }
            XMEMSET(keep, 0, sizeof(*keep));
            *devCtxPtr = keep;
        }

        ret = _wc_Hash_Grow(&keep->msg, &keep->used, &keep->len,
            info->hash.in, (int)info->hash.inSz, NULL);
        if (ret != 0) {
            return ret;
        }
    }

    /* final: hash the saved message in one engine call, then free it. */
    if (info->hash.digest != NULL) {
        wc_NuvotonShaReq req;

        XMEMSET(&req, 0, sizeof(req));
        req.shaMode  = shaMode;
        req.dmaMode  = WC_NUVOTON_DMA_ONE_SHOT;
        req.digest   = info->hash.digest;
        req.digestSz = hashLen;
        if (keep != NULL) {
            req.in   = keep->msg;
            req.inSz = keep->used;
        }

        ret = wc_nuvoton_hw_sha(&req);

        /* An empty message, or one the DMA engine cannot address, is handed
         * back to software rather than failed. The saved message is released
         * either way: wolfCrypt still holds the full software hash state, so
         * the fallback recomputes from that and not from this buffer. */
        if (ret == WC_NO_ERR_TRACE(BAD_LENGTH_E) ||
            ret == WC_NO_ERR_TRACE(BAD_ALIGN_E)) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }

        if (keep != NULL) {
            wc_NuvotonHashKeepFree(keep);
            *devCtxPtr = NULL;
        }

        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

int wc_NuvotonCb_Hash(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_NuvotonHashCompute(info);
}

#ifdef WOLF_CRYPTO_CB_COPY
int wc_NuvotonCb_HashCopy(wc_CryptoInfo* info)
{
    void**           srcDevCtx;
    void**           dstDevCtx;
    NuvotonHashKeep* srcKeep;
    NuvotonHashKeep* dstKeep;
    word32           ctxSize;
    int              ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->copy.algo != WC_ALGO_TYPE_HASH) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    srcDevCtx = wc_NuvotonHashDevCtx(info->copy.src, info->copy.type);
    dstDevCtx = wc_NuvotonHashDevCtx(info->copy.dst, info->copy.type);
    ctxSize   = wc_NuvotonHashCtxSize(info->copy.type);
    if (srcDevCtx == NULL || dstDevCtx == NULL || ctxSize == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* wolfSSL skips its own copy when this succeeds, so do all of it. Free
     * anything the destination already holds or it would leak. */
    wc_NuvotonHashKeepFree((NuvotonHashKeep*)(*dstDevCtx));

    /* Copy the whole struct, then give the destination its own copy of the
     * saved message so the two do not share a buffer. */
    XMEMCPY(info->copy.dst, info->copy.src, ctxSize);

    srcKeep = (NuvotonHashKeep*)(*srcDevCtx);
    if (srcKeep == NULL) {
        *dstDevCtx = NULL;
        return 0;
    }

    dstKeep = (NuvotonHashKeep*)XMALLOC(sizeof(NuvotonHashKeep), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (dstKeep == NULL) {
        *dstDevCtx = NULL;
        return MEMORY_E;
    }
    XMEMSET(dstKeep, 0, sizeof(*dstKeep));

    if (srcKeep->used > 0) {
        ret = _wc_Hash_Grow(&dstKeep->msg, &dstKeep->used, &dstKeep->len,
            srcKeep->msg, (int)srcKeep->used, NULL);
        if (ret != 0) {
            wc_NuvotonHashKeepFree(dstKeep);
            *dstDevCtx = NULL;
            return ret;
        }
    }

    *dstDevCtx = dstKeep;
    return 0;
}
#endif /* WOLF_CRYPTO_CB_COPY */

#ifdef WOLF_CRYPTO_CB_FREE
/* Release the saved message a hash context is holding. Called from
 * wc_NuvotonCb_Free() for WC_ALGO_TYPE_HASH objects. */
int wc_NuvotonHashFree(wc_CryptoInfo* info)
{
    void**           devCtx;
    NuvotonHashKeep* keep;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    devCtx = wc_NuvotonHashDevCtx(info->free.obj, info->free.type);
    if (devCtx != NULL) {
        keep = (NuvotonHashKeep*)(*devCtx);
        if (keep != NULL) {
            wc_NuvotonHashKeepFree(keep);
            *devCtx = NULL;
        }
    }

    /* Decline so wolfSSL still wipes the context. devCtx is NULL now, so
     * nothing gets freed twice. */
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* WOLF_CRYPTO_CB_FREE */

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_HASH && WOLF_CRYPTO_CB */
