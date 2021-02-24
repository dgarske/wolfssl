/* se050_port.h
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

#ifndef _SE050_PORT_H_
#define _SE050_PORT_H_

#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#include "fsl_sss_api.h"


#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>

/*#define kAlgorithm_SSS_SHA1     1
#define kAlgorithm_SSS_SHA224   2
#define kAlgorithm_SSS_SHA256   3
#define kAlgorithm_SSS_SHA384   4
#define kAlgorithm_SSS_SHA512   5*/


/* STM32 register size in bytes */
#define SE050_HASH_REG_SIZE  4

#ifndef WOLFSSL_MAX_HASH_SIZE
    #define WOLFSSL_MAX_HASH_SIZE  64
#endif

typedef struct {
    /* const */ byte*  msg;
    void*  heap;
    word32 used;
    word32 len;
    //word32 sha_type;
} wolfssl_SE050_Hash;





WOLFSSL_API int wolfcrypt_se050_SetConfig(sss_session_t *pSession);
WOLFSSL_API int se050_init(void);

int se050_get_random_number(uint32_t count, uint8_t* rand_out);


//these two are used in the hash part...
/* void wc_Se050_Hash_SaveContext(sss_digest_t* digest_ctx);
 int wc_Se050_Hash_RestoreContext(sss_digest_t* digest_ctx);

int hashInit(wolfssl_SE050_Hash *hash);
int hashUpdate(wolfssl_SE050_Hash *hash, const byte* data, word32 len);
int hashFinal(wolfssl_SE050_Hash *hash, byte* result, word32 algo, word32 *hsize);
void hashFree(wolfssl_SE050_Hash *hash);

int hashGetHash(wolfssl_SE050_Hash *hash, byte* result, word32 algo, word32 hsize);
int hashCopy(wolfssl_SE050_Hash *src, wolfssl_SE050_Hash *dst);*/


int se050_hash_init(wolfssl_SE050_Hash* tmpHash, void* heap, int devId);
int se050_hash_update(wolfssl_SE050_Hash* tmpHash, const byte* data, word32 len);
int se050_hash_final(wolfssl_SE050_Hash* tmpHash, byte* hash, size_t digestLen, word32 algo);
void se050_hash_free(wolfssl_SE050_Hash* tmpHash);


/*int se050_sha256_init(wc_Sha256* sha256);
int se050_sha256_update(wc_Sha256* sha256, const byte* data, word32 len);
int se050_sha256_final(wc_Sha256* sha256, byte* hash);
void se050_sha256_free(wc_Sha256* sha256);*/

#endif /* _SE050_PORT_H_ */
