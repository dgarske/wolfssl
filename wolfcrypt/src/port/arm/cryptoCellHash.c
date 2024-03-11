/* cryptoCellHash.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* This source is included in wc_port.c */
/* WOLFSSL_CRYPTOCELL_HASH_C is defined by wc_port.c in case compile tries
    to include this .c directly */
#ifdef WOLFSSL_CRYPTOCELL_HASH_C

#if !defined(NO_SHA256) && \
    (defined(WOLFSSL_CRYPTOCELL) || defined(WOLFSSL_CRYPTOCELL_312))

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/port/arm/cryptoCell.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_CRYPTOCELL_312)

#if 0
int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    drvError_t ret = 0;
    HashContext_t *pHashCtx = NULL;

    (void)devId;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    pHashCtx = (HashContext_t *)&sha256->ctx;

    XMEMSET(sha256, 0, sizeof(*sha256));
    sha256->heap = heap;
    pHashCtx->mode = HASH_SHA256;
    pHashCtx->blockSizeInBytes = WC_SHA256_BLOCK_SIZE;

    /* initializes the HASH context and machine to the supported mode.*/
    ret = InitHashDrv(pHashCtx);
    if (ret != HASH_DRV_OK){
        WOLFSSL_MSG("Error InitHashDrv failed");
    }

    return ret;
}

#if 0
static int Transform_Sha256(wc_Sha256* sha256, const byte* data)
{
    drvError_t ret;
    CCBuffInfo_t inBuf;

    ret = CC_PalDataBufferAttrGet(data, WC_SHA256_BLOCK_SIZE, INPUT_DATA_BUFFER,
        &inBuf.dataBuffNs);
    if (ret == HASH_DRV_OK) {
        inBuf.dataBuffAddr = (uint32_t)data;
        ret = ProcessHashDrv(&sha256->ctx, &inBuf, WC_SHA256_BLOCK_SIZE);
    }
    if (ret != HASH_DRV_OK) {
        WOLFSSL_MSG("CryptoCell-312 SHA256 error");
        return WC_HW_E;
    }
    return (int)ret;
}
#endif

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
	int rc = 0;
    HashContext_t *pHashCtx = NULL;
    size_t         bytesToAdd = 0;
    uint32_t       localPrevDataIn[WC_SHA256_BLOCK_SIZE];
    CCBuffInfo_t   inBuffInfo;

    if (sha256 == NULL || (len > 0 && data == NULL))
        return BAD_FUNC_ARG;

    pHashCtx = (HashContext_t *)&sha256->ctx;
    /* If pHashCtx->prevDataInSize > 0, fill it with with the current data */
    bytesToAdd = ((pHashCtx->blockSizeInBytes - pHashCtx->prevDataInSize) % pHashCtx->blockSizeInBytes);
    if (bytesToAdd > len)
        bytesToAdd = len;
    if (bytesToAdd > 0) {
        /* add the data to the remaining buffer */
        XMEMCPY(&(((uint8_t *)(pHashCtx->prevDataIn))[pHashCtx->prevDataInSize]), data, bytesToAdd);
        pHashCtx->prevDataInSize += bytesToAdd;
        data += bytesToAdd;
        len -= bytesToAdd;
    }

    /* If the remaining buffer is full, process the block (else, the remaining buffer will be processed in the next update or finish) */
    if (pHashCtx->prevDataInSize == pHashCtx->blockSizeInBytes) {
        /* Copy prevDataIn to stack, in order to ensure continues and physical memory access.
         * That way, DMA will be able to access the data on any platform.*/
        size_t sz = min(WC_SHA256_BLOCK_SIZE*sizeof(uint32_t), pHashCtx->prevDataInSize);
        XMEMCPY(localPrevDataIn, pHashCtx->prevDataIn, sz);

        rc = SetDataBuffersInfo((uint8_t*)localPrevDataIn, pHashCtx->blockSizeInBytes, &inBuffInfo,
                                   NULL, 0, NULL);
        if (rc != 0) {
             WOLFSSL_MSG("illegal data buffers");
             return rc;
        }

        rc = ProcessHashDrv(pHashCtx, &inBuffInfo, pHashCtx->blockSizeInBytes);
        if (rc != HASH_DRV_OK) {
            WOLFSSL_MSG( "ProcessHashDrv failed"); //, ret = %d\n", rc );
            return rc;
        }
        pHashCtx->prevDataInSize = 0;
    }

    /* Process all the blocks that remain in the data */
    bytesToAdd = (len / pHashCtx->blockSizeInBytes) * pHashCtx->blockSizeInBytes;
    if (bytesToAdd > 0) {

        rc = SetDataBuffersInfo(data, bytesToAdd, &inBuffInfo, NULL, 0, NULL);
        if (rc != HASH_DRV_OK) {
             WOLFSSL_MSG("illegal data buffers");
             return rc;
        }

        rc = ProcessHashDrv(pHashCtx, &inBuffInfo, bytesToAdd);
        if (rc != HASH_DRV_OK) {
            WOLFSSL_MSG("ProcessHashDrv failed"); //, ret = %d\n", rc);
            return rc;
        }
        data += bytesToAdd;
        len -= bytesToAdd;
    }

    /* Copy the remaining partial block to prevDataIn */
    bytesToAdd = len;
    if (bytesToAdd > 0) {
        XMEMCPY((uint8_t *)&((pHashCtx->prevDataIn)[pHashCtx->prevDataInSize]), data, bytesToAdd);
        pHashCtx->prevDataInSize += bytesToAdd;
    }
    return 0;
}
int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int rc = HASH_DRV_OK;
    uint32_t       localPrevDataIn[WC_SHA256_BLOCK_SIZE];
    size_t         dataInSize = 0;
    HashContext_t *pHashCtx = NULL;
    CCBuffInfo_t   inBuffInfo;

    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    pHashCtx = (HashContext_t *)&sha256->ctx;
    if (pHashCtx->prevDataInSize != 0) {
        /* Copy prevDataIn to stack, in order to ensure continues and physical memory access.
         * That way, DMA will be able to access the data on any platform.*/
        XMEMCPY(localPrevDataIn, pHashCtx->prevDataIn,
            min(WC_SHA256_BLOCK_SIZE*sizeof(uint32_t), pHashCtx->prevDataInSize));
        dataInSize = pHashCtx->prevDataInSize;
    }
    pHashCtx->isLastBlockProcessed = 1;

    rc = SetDataBuffersInfo((uint8_t*)localPrevDataIn, dataInSize, &inBuffInfo,
        NULL, 0, NULL);
    if (rc != HASH_DRV_OK) {
         WOLFSSL_MSG("illegal data buffers");
         return 1;
    }

    rc = ProcessHashDrv(pHashCtx, &inBuffInfo, dataInSize);
    if (rc != HASH_DRV_OK){
        WOLFSSL_MSG("ProcessHashDrv failed"); //, ret = %d\n", rc);
        return 1;
    }
    rc = FinishHashDrv(pHashCtx);
    if (rc != HASH_DRV_OK) {
        WOLFSSL_MSG("FinishHashDrv failed"); //, ret = %d\n", rc);
        return 1;
    }
    pHashCtx->prevDataInSize = 0;

    XMEMCPY(hash, pHashCtx->digest, WC_SHA256_DIGEST_SIZE);

    return 0;
}
#endif

#else

int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    CRYSError_t ret = 0;

    (void)heap;
    (void)devId;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha256->digest, 0, sizeof(sha256->digest));

    /* initializes the HASH context and machine to the supported mode.*/
    ret = CRYS_HASH_Init(&sha256->ctx, CRYS_HASH_SHA256_mode);

    if (ret != SA_SILIB_RET_OK){
        WOLFSSL_MSG("Error CRYS_HASH_Init failed");
    }

    return ret;
}

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    CRYSError_t         ret = 0;
    size_t              length;
    size_t              remaining = len;
    byte const *        p_cur     = data;

    if (sha256 == NULL || (data == NULL && len > 0)) {
        return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* If the input is larger than CC310_MAX_LENGTH_DMA, split into smaller */
    do {
        length = (remaining > CC310_MAX_LENGTH_DMA) ?
                    CC310_MAX_LENGTH_DMA : remaining;

        ret = CRYS_HASH_Update(&sha256->ctx, (uint8_t *)p_cur, length);

        remaining -= length;
        p_cur += length;

    } while (ret == CRYS_OK && remaining > 0);

    return ret;
}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    CRYSError_t ret = 0;
    CRYS_HASH_Result_t hashResult;

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = CRYS_HASH_Finish(&sha256->ctx, hashResult);

    if (ret != SA_SILIB_RET_OK){
        WOLFSSL_MSG("Error CRYS_HASH_Finish failed");
        return ret;
    }
    XMEMCPY(sha256->digest, hashResult, WC_SHA256_DIGEST_SIZE);

    XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);

    /* reset state */
    return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
}

#endif /* WOLFSSL_CRYPTOCELL || WOLFSSL_CRYPTOCELL_312 */

#if 0
int wc_InitSha256(Sha256* sha256)
{
    return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
}

void wc_Sha256Free(wc_Sha256* sha256)
{
    if (sha256 == NULL)
        return;
}
#endif

#endif /* !NO_SHA256 */
#endif /* WOLFSSL_CRYPTOCELL_HASH_C */
