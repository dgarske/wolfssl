/* puf.h
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

/*!
    \file wolfssl/wolfcrypt/puf.h
*/

#ifndef WOLF_CRYPT_PUF_H
#define WOLF_CRYPT_PUF_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_PUF

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* BCH(127,64,t=10) parameters */
#define WC_PUF_BCH_M          7    /* GF(2^7) */
#define WC_PUF_BCH_N        127    /* codeword length */
#define WC_PUF_BCH_K         64    /* message length */
#define WC_PUF_BCH_T         10    /* error correction capability */

/* PUF dimensions */
#define WC_PUF_NUM_CODEWORDS  16   /* 16 codewords */
#define WC_PUF_RAW_BITS    2048    /* 16 x 128 bits (rounded up for storage) */
#define WC_PUF_RAW_BYTES   (WC_PUF_RAW_BITS / 8)  /* 256 bytes */
#define WC_PUF_STABLE_BITS 1024    /* 16 x 64 message bits */
#define WC_PUF_STABLE_BYTES (WC_PUF_STABLE_BITS / 8)  /* 128 bytes */

/* Helper data: 16 codewords x 127 bits, packed into bytes */
#define WC_PUF_HELPER_BITS  (WC_PUF_NUM_CODEWORDS * WC_PUF_BCH_N)
#define WC_PUF_HELPER_BYTES ((WC_PUF_HELPER_BITS + 7) / 8)  /* 254 bytes */

/* Output key size */
#define WC_PUF_KEY_SZ         32   /* 256-bit derived key */

/* Identity hash size */
#define WC_PUF_ID_SZ          32   /* SHA-256 hash of stable bits */

/* Flags for PufCtx.flags */
#define WC_PUF_FLAG_ENROLLED  0x01
#define WC_PUF_FLAG_READY     0x02

typedef struct PufCtx {
    byte  rawSram[WC_PUF_RAW_BYTES];         /* raw SRAM readout */
    byte  helperData[WC_PUF_HELPER_BYTES];   /* enrollment helper data */
    byte  stableBits[WC_PUF_STABLE_BYTES];   /* reconstructed stable bits */
    byte  identity[WC_PUF_ID_SZ];            /* device identity hash */
    word32 flags;

#ifdef WOLFSSL_PUF_TEST
    const byte* testSram;                    /* injected test SRAM data */
    word32 testSramSz;
#endif
} PufCtx;

WOLFSSL_API int wc_PufInit(PufCtx* ctx);
WOLFSSL_API int wc_PufReadSram(PufCtx* ctx, const byte* sramAddr,
                               word32 sramSz);
WOLFSSL_API int wc_PufEnroll(PufCtx* ctx);
WOLFSSL_API int wc_PufReconstruct(PufCtx* ctx, const byte* helperData,
                                  word32 helperSz);
WOLFSSL_API int wc_PufDeriveKey(PufCtx* ctx, const byte* info, word32 infoSz,
                                byte* key, word32 keySz);
WOLFSSL_API int wc_PufGetIdentity(PufCtx* ctx, byte* id, word32 idSz);
WOLFSSL_API int wc_PufZeroize(PufCtx* ctx);

#ifdef WOLFSSL_PUF_TEST
WOLFSSL_API int wc_PufSetTestData(PufCtx* ctx, const byte* data, word32 sz);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_PUF */

#endif /* WOLF_CRYPT_PUF_H */
