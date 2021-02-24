/* se050_port.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>



#if defined(WOLFSSL_SE050)

#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#include "fsl_sss_api.h"


/*#define kAlgorithm_SSS_SHA1 1
#define kAlgorithm_SSS_SHA224 2
#define kAlgorithm_SSS_SHA256 3
#define kAlgorithm_SSS_SHA384 4
#define kAlgorithm_SSS_SHA512 5*/


static sss_session_t *cfg_se050_i2c_pi;

int se050_init(void) //sets up some other things, called by wc_port (need to add that part)
{
	printf("this runs");
	return 0;
	
}

int wolfcrypt_se050_SetConfig(sss_session_t *pSession) 
{
	printf("Setting SE050 session configuration\n");
	
	XMEMSET(&cfg_se050_i2c_pi, 0, sizeof(cfg_se050_i2c_pi));
	cfg_se050_i2c_pi = pSession;	
	
	
	return 0;
}


int se050_get_random_number(uint32_t count, uint8_t* rand_out)
{
    sss_status_t status;
	sss_rng_context_t rng;


    status = sss_rng_context_init(&rng, cfg_se050_i2c_pi);
    if (status != kStatus_SSS_Success) {
        return -1;
    }

    status = sss_rng_get_random(&rng, rand_out, count);
    if (status != kStatus_SSS_Success) {
	    return -1;
    }

    status = sss_rng_context_free(&rng);
    if (status != kStatus_SSS_Success) {
        return -1;
    }

    return 0;    
}

int se050_hash_init(wolfssl_SE050_Hash* tmpHash, void* heap, int devId)
{
    (void)devId;
    //wolfssl_SE050_Hash* tmpHash = (wolfssl_SE050_Hash *)sha;

    tmpHash->heap = heap;
    tmpHash->len  = 0;
    tmpHash->used = 0;
    tmpHash->msg  = NULL;
    return 0;

}

int se050_hash_update(wolfssl_SE050_Hash* tmpHash, const byte* data, word32 len)
{
    //wolfssl_SE050_Hash* tmpHash = (wolfssl_SE050_Hash *)sha;
    if (tmpHash == NULL || (len > 0 && data == NULL)) {
        return -1;
    }
    
    if (tmpHash->len < tmpHash->used + len) {
        if (tmpHash->msg == NULL) {
            tmpHash->msg = (byte*)XMALLOC(tmpHash->used + len, tmpHash->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
        } 
        else {
            byte* pt = (byte*)XREALLOC(tmpHash->msg, tmpHash->used + len, tmpHash->heap,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (pt == NULL) {
                return -1;
            }
            tmpHash->msg = pt;
        }
        tmpHash->len = tmpHash->used + len;
    }
    XMEMCPY(tmpHash->msg + tmpHash->used, data , len);
    tmpHash->used += len;
    return 0;
}

int se050_hash_final(wolfssl_SE050_Hash* tmpHash, byte* hash, size_t digestLen, sss_algorithm_t algo)
{
    sss_status_t status;
    sss_digest_t digest_ctx;
    XMEMSET(&digest_ctx, 0, sizeof(digest_ctx));
    
    //wolfssl_SE050_Hash* tmpHash = (wolfssl_SE050_Hash *)sha;
    const byte* data = tmpHash->msg; 



    status = sss_digest_context_init(&digest_ctx, cfg_se050_i2c_pi, algo, kMode_SSS_Digest);  
    if(status != kStatus_SSS_Success){
        printf("error 1\n");
        return -1;
    }

    /*status = sss_digest_init(&digest_ctx);
    if(status != kStatus_SSS_Success){
        printf("error 2\n");
        return -1;
    }
    
    status = sss_digest_update(&digest_ctx, data, tmpHash->len);
    if(status != kStatus_SSS_Success){
        printf("error 3\n");
        return -1;
    }
    
    status = sss_digest_finish(&digest_ctx, hash, &digestLen);
    if(status != kStatus_SSS_Success){
        printf("error 4\n");
        return -1;
    }*/
    
    status = sss_digest_one_go(&digest_ctx, data, tmpHash->len, hash, &digestLen);
    if(status != kStatus_SSS_Success){
        printf("error 4\n");
        return -1;
    }

    sss_digest_context_free(&digest_ctx);
    return 0;
}

void se050_hash_free(wolfssl_SE050_Hash* tmpHash)
{
    
    //sss_digest_context_free(&sha->digest_ctx);
    //(void)sha->digest_ctx;
    (void)tmpHash;

}

/*int se050_sha256_init(wc_Sha256* sha256)
{
    sss_status_t status; 

    if (sha256->flags & WC_HASH_FLAG_ISCOPY) {
        return 0;
    }
    else {
        status = sss_digest_context_init(&sha256->digest_ctx, cfg_se050_i2c_pi, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
        if(status != kStatus_SSS_Success){
            return -1;
        }
        status = sss_digest_init(&sha256->digest_ctx);
        if(status != kStatus_SSS_Success){
            return -1;
        }
    }
    return 0;

}

int se050_sha256_update(wc_Sha256* sha256, const byte* data, word32 len)
{
    sss_status_t status;

    status = sss_digest_update(&sha256->digest_ctx, data, len);

    if(status != kStatus_SSS_Success){
        return -1;
    }
    return 0;


}

int se050_sha256_final(wc_Sha256* sha256, byte* hash)
{
    sss_status_t status;
    size_t digestLen = WC_SHA_DIGEST_SIZE; 

    
    status = sss_digest_finish(&sha256->digest_ctx, hash, &digestLen);

    if(status != kStatus_SSS_Success){
        return -1;
    }
    return 0;
}

void se050_sha256_free(wc_Sha256* sha256)
{
    
    
    if(sha256 != NULL) {
        if (sha256->flags & WC_HASH_FLAG_ISCOPY){
            (void)sha256;
        }
        else{
            sss_digest_context_free(&sha256->digest_ctx);
        }
    }

}*/

#endif /* SE050 */
