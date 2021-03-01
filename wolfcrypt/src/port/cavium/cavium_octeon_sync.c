/* cavium_octeon_sync.c
 *
 * Copyright(C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.(formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef HAVE_CAVIUM_OCTEON_SYNC

/* Setting NO_MAIN_DRIVER here because this file ends up building
 * in the library sources which doesn't have NO_MAIN_DRIVER set,
 * as the library expects main to be somewhere else. */
#undef NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#include <wolfssl/wolfcrypt/port/cavium/cavium_octeon_sync.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "cvmx.h"
#include "cvmx-asm.h"
#include "cvmx-key.h"
#include "cvmx-swap.h"

#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif
#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#define NOOPT __attribute__((optimize("O0")))

static int devId = 1234;

#ifndef NO_SHA
int
SHA1_Update (wc_Sha * c, const void *data, size_t n)
{
  unsigned long remaining = 0, totlen = 0, copied = 0;
  const uint64_t *ptr = (const uint64_t *) data;

     
  if(!n) 
    return -1;

  totlen = n;

  if (c->buffLen) {
    totlen += remaining = c->buffLen;
    memcpy ((char *) &(c->buffer) + remaining, data,
        WC_SHA_BLOCK_SIZE - remaining);
    copied = 1;
  }
  if (totlen >= 64) {
    /* Get the running IV loaded */
    word64 E = (((word64)c->digest[0]) << 32) | c->digest[1];
    word64 F = (((word64)c->digest[2]) << 32) | c->digest[3];
    word64 G = (((word64)c->digest[4]) << 32);

    CVMX_MT_HSH_IV (E, 0);
    CVMX_MT_HSH_IV (F, 1);
    CVMX_MT_HSH_IV (G, 2);

    /* Iterate through 64 bytes at a time */
    while (totlen >= 64) {
      if (copied)
        copied = 0;
      if (remaining)
        ptr = (uint64_t *) & c->buffer;
      CVMX_MT_HSH_DAT (*ptr++, 0);
      CVMX_MT_HSH_DAT (*ptr++, 1);
      CVMX_MT_HSH_DAT (*ptr++, 2);
      CVMX_MT_HSH_DAT (*ptr++, 3);
      CVMX_MT_HSH_DAT (*ptr++, 4);
      CVMX_MT_HSH_DAT (*ptr++, 5);
      CVMX_MT_HSH_DAT (*ptr++, 6);
      CVMX_MT_HSH_STARTSHA (*ptr++);
      CVMX_PREFETCH(ptr, 64);
      totlen -= 64;
      /* remainig reset set ptr to input data */
      if (remaining) {
        ptr = (uint64_t*)((char*)data + (WC_SHA_BLOCK_SIZE - remaining));
        remaining = 0;
      }
    }
    /* Update the IV */
    CVMX_MF_HSH_IV (E, 0);
    CVMX_MF_HSH_IV (F, 1);
    CVMX_MF_HSH_IV (G, 2);

    c->digest[0] = E >> 32;
    c->digest[1] = (word32)E;
    c->digest[2] = F >> 32;
    c->digest[3] = (word32)F;
    c->digest[4] = G >> 32;
  }                             /* end of if(totlen) */
  word32 tmp = c->loLen;
  if ((c->loLen += n) < tmp)
    c->hiLen++;                       /* carry low to high */
  if (!copied)
    memcpy (&(c->buffer), ptr, totlen);
  c->buffLen = totlen;
  return 1;
}

int
SHA1_Final (unsigned char *md, wc_Sha * c)
{
  uint64_t bits = (((uint64_t)c->hiLen) << 35) + (((uint64_t)c->loLen) << 3);
  unsigned long len = c->loLen % 64;
  uint8_t chunk[64];
  const uint64_t *ptr;

  /* The rest of the data will need to be copied into a chunk */
  if (len > 0)
    memcpy (chunk, c->buffer, len);
  chunk[len] = 0x80;
  memset (chunk + len + 1, 0, 64 - len - 1);
  /* Get the running IV loaded */
  word64 E = (((word64)c->digest[0]) << 32) | c->digest[1];
  word64 F = (((word64)c->digest[2]) << 32) | c->digest[3];
  word64 G = (((word64)c->digest[4]) << 32);

  CVMX_MT_HSH_IV (E, 0);
  CVMX_MT_HSH_IV (F, 1);
  CVMX_MT_HSH_IV (G, 2);

  ptr = (const uint64_t *) chunk;
  CVMX_MT_HSH_DAT (*ptr++, 0);
  CVMX_MT_HSH_DAT (*ptr++, 1);
  CVMX_MT_HSH_DAT (*ptr++, 2);
  CVMX_MT_HSH_DAT (*ptr++, 3);
  CVMX_MT_HSH_DAT (*ptr++, 4);
  CVMX_MT_HSH_DAT (*ptr++, 5);
  CVMX_MT_HSH_DAT (*ptr++, 6);

  /* Check to see if there is room for the bit count */
  if (len < 56)
    CVMX_MT_HSH_STARTSHA (bits);
  else {
    CVMX_MT_HSH_STARTSHA (*ptr);
    /* Another block was needed */
    CVMX_MT_HSH_DATZ (0);
    CVMX_MT_HSH_DATZ (1);
    CVMX_MT_HSH_DATZ (2);
    CVMX_MT_HSH_DATZ (3);
    CVMX_MT_HSH_DATZ (4);
    CVMX_MT_HSH_DATZ (5);
    CVMX_MT_HSH_DATZ (6);
    CVMX_MT_HSH_STARTSHA (bits);
  }
  /* Update the IV */
  CVMX_MF_HSH_IV (E, 0);
  CVMX_MF_HSH_IV (F, 1);
  CVMX_MF_HSH_IV (G, 2);
  cvmx_usd(md, E);
  cvmx_usd(md + 8, F);
  cvmx_usw(md + 16, G >> 32);
//   CVMX_STOREUNA_INT64(E, md, 0);
//   CVMX_STOREUNA_INT64(F, md, 8);
//   CVMX_STOREUNA_INT32(G >> 32, md, 16);
  c->digest[0] = 0x67452301L;
  c->digest[1] = 0xEFCDAB89L;
  c->digest[2] = 0x98BADCFEL;
  c->digest[3] = 0x10325476L;
  c->digest[4] = 0xC3D2E1F0L;
  c->buffLen = 0;
  c->loLen   = 0;
  c->hiLen   = 0;
  return 1;
}

static int Octeon_Sha_Hash(wc_Sha* sha, byte* in, word32 inSz, byte* out)
{
    if (sha == NULL || (in == NULL && out == NULL))
        return BAD_FUNC_ARG;

    if (in)
        SHA1_Update(sha, in, inSz);
    if (out)
        SHA1_Final(out, sha);

    return 0;
}
#endif

#if !defined(NO_SHA256)
int
SHA256_Update (wc_Sha256 * ctx, const void *data, size_t len)
{
    uint8_t *pbuf = (uint8_t *)&ctx->buffer[0];
  //Increment totalin
  word32 tmp = ctx->loLen;
  if ((ctx->loLen += len) < tmp)
    ctx->hiLen++;                       /* carry low to high */

  if ((ctx->buffLen + len) >= 64) {
    //restore IV
    CVMX_MT_HSH_IV (ctx->iv[0], 0);
    CVMX_MT_HSH_IV (ctx->iv[1], 1);
    CVMX_MT_HSH_IV (ctx->iv[2], 2);
    CVMX_MT_HSH_IV (ctx->iv[3], 3);

    if (ctx->buffLen) {
      memcpy (pbuf + ctx->buffLen, data, 64 - ctx->buffLen);
      len -= (64 - ctx->buffLen);
      data = (uint8_t *) data + (64 - ctx->buffLen);
      ctx->buffLen = 0;
      uint64_t *ptr = (uint64_t *) pbuf;
      CVMX_MT_HSH_DAT (*ptr++, 0);
      CVMX_MT_HSH_DAT (*ptr++, 1);
      CVMX_MT_HSH_DAT (*ptr++, 2);
      CVMX_MT_HSH_DAT (*ptr++, 3);
      CVMX_MT_HSH_DAT (*ptr++, 4);
      CVMX_MT_HSH_DAT (*ptr++, 5);
      CVMX_MT_HSH_DAT (*ptr++, 6);
      CVMX_MT_HSH_STARTSHA256 (*ptr++);
    }

    uint64_t *ptr = (uint64_t *) data;
    while (len >= 64) {
      CVMX_MT_HSH_DAT (*ptr++, 0);
      CVMX_MT_HSH_DAT (*ptr++, 1);
      CVMX_MT_HSH_DAT (*ptr++, 2);
      CVMX_MT_HSH_DAT (*ptr++, 3);
      CVMX_MT_HSH_DAT (*ptr++, 4);
      CVMX_MT_HSH_DAT (*ptr++, 5);
      CVMX_MT_HSH_DAT (*ptr++, 6);
      CVMX_MT_HSH_STARTSHA256 (*ptr++);
      len -= 64;
    }

    if (len) {
      memcpy (pbuf, ptr, len);
      ctx->buffLen = len;
    }
    //save IV
    CVMX_MF_HSH_IV (ctx->iv[0], 0);
    CVMX_MF_HSH_IV (ctx->iv[1], 1);
    CVMX_MF_HSH_IV (ctx->iv[2], 2);
    CVMX_MF_HSH_IV (ctx->iv[3], 3);
  } else {
    memcpy (&pbuf[ctx->buffLen], data, len);
    ctx->buffLen += len;
  }

  return 1;
}

int
SHA256_Final (unsigned char *md, wc_Sha256 * ctx)
{
    uint64_t bits = (((uint64_t)ctx->hiLen) << 35) + (((uint64_t)ctx->loLen) << 3);

    //RESTORE IV
    CVMX_MT_HSH_IV (ctx->iv[0], 0);
    CVMX_MT_HSH_IV (ctx->iv[1], 1);
    CVMX_MT_HSH_IV (ctx->iv[2], 2);
    CVMX_MT_HSH_IV (ctx->iv[3], 3);

    uint8_t *pbuf = (uint8_t *)&ctx->buffer[0];
    pbuf[ctx->buffLen] = 0x80;
    memset (pbuf + ctx->buffLen + 1, 0, 64 - ctx->buffLen - 1);

    uint64_t *ptr = (uint64_t *) pbuf;
    CVMX_MT_HSH_DAT (*ptr++, 0);
    CVMX_MT_HSH_DAT (*ptr++, 1);
    CVMX_MT_HSH_DAT (*ptr++, 2);
    CVMX_MT_HSH_DAT (*ptr++, 3);
    CVMX_MT_HSH_DAT (*ptr++, 4);
    CVMX_MT_HSH_DAT (*ptr++, 5);
    CVMX_MT_HSH_DAT (*ptr++, 6);
    if (ctx->buffLen < 56) {
      CVMX_MT_HSH_STARTSHA256 (bits);
    } else {
      CVMX_MT_HSH_STARTSHA256 (*ptr);
      /* Another block was needed */
      CVMX_MT_HSH_DATZ (0);
      CVMX_MT_HSH_DATZ (1);
      CVMX_MT_HSH_DATZ (2);
      CVMX_MT_HSH_DATZ (3);
      CVMX_MT_HSH_DATZ (4);
      CVMX_MT_HSH_DATZ (5);
      CVMX_MT_HSH_DATZ (6);
      CVMX_MT_HSH_STARTSHA256 (bits);
    }

    //WRITE IV
    CVMX_MF_HSH_IV (((uint64_t *) md)[0], 0);
    CVMX_MF_HSH_IV (((uint64_t *) md)[1], 1);
    CVMX_MF_HSH_IV (((uint64_t *) md)[2], 2);
    // if (ctx->sha256) {
      CVMX_MF_HSH_IV (((uint64_t *) md)[3], 3);
    // } else {
    //   CVMX_MF_HSH_IV (ctx->iv[3], 3);
    //   memcpy (md + 24, &ctx->iv[3], 4);
    // }

    ctx->iv[0] = 0x6a09e667bb67ae85ull;
    ctx->iv[1] = 0x3c6ef372a54ff53aull;
    ctx->iv[2] = 0x510e527f9b05688cull;
    ctx->iv[3] = 0x1f83d9ab5be0cd19ull;
    ctx->buffLen = 0;
    ctx->loLen   = 0;
    ctx->hiLen   = 0;

  return 1;
}

static int Octeon_Sha256_Hash(wc_Sha256* sha, byte* in, word32 inSz, byte* out)
{
    if (sha == NULL || (in == NULL && out == NULL))
        return BAD_FUNC_ARG;

    if (in)
        SHA256_Update(sha, in, inSz);
    if (out)
        SHA256_Final(out, sha);

    return 0;
}
#endif

#ifndef NO_DES3
static int Octeon_Des3_CbcEncrypt(Des3* des3,
        uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, r0;
    uint64_t *key, *iv;

    if (des3 == NULL || inp64 == NULL || outp64 == NULL)
        return BAD_FUNC_ARG;

    /* expects 64-bit aligned value */
    key = (uint64_t*)des3->devKey;
    CVMX_MT_3DES_KEY(key[0], 0);
    CVMX_MT_3DES_KEY(key[1], 1);
    CVMX_MT_3DES_KEY(key[2], 2);
    iv = (uint64_t*)des3->reg;
    CVMX_MT_3DES_IV(iv[0]);

    CVMX_PREFETCH0(inp64);

    i0 = *inp64;

    /* DES3 assembly can handle 16-byte chunks */
    if (inl >= 16) {
        CVMX_MT_3DES_ENC_CBC(i0);
        inl -= 8;
        inp64++;
        outp64++;

        if (inl >= 8) {
           i0 = inp64[0];
           CVMX_MF_3DES_RESULT(r0);
           CVMX_MT_3DES_ENC_CBC(i0);

            for (;;) {
                outp64[-1] = r0;
                inl -= 8;
                inp64++;
                outp64++;
                i0 = *inp64;

                if (inl < 8)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_3DES_RESULT(r0);
                CVMX_MT_3DES_ENC_CBC(i0);
            }
        }
        CVMX_MF_3DES_RESULT(r0);
        outp64[-1] = r0;
    }
    /* remainder */
    if (inl > 0) {
        uint64_t r = 0;
        if (inl <= 8) {
            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_ENC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
        else {
            i0 = *inp64;
            CVMX_MT_3DES_ENC_CBC(i0);
            CVMX_MF_3DES_RESULT(*outp64);
            inp64++, outp64++;

            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_ENC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
    }

    CVMX_MT_3DES_IV(iv[0]);

    return 0;
}

static int Octeon_Des3_CbcDecrypt(Des3* des3,
        uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, r0;
    uint64_t *key, *iv;

    if (des3 == NULL || inp64 == NULL || outp64 == NULL)
        return BAD_FUNC_ARG;

    /* expects 64-bit aligned value */
    key = (uint64_t*)des3->devKey;
    CVMX_MT_3DES_KEY(key[0], 0);
    CVMX_MT_3DES_KEY(key[1], 1);
    CVMX_MT_3DES_KEY(key[2], 2);

    iv = (uint64_t*)des3->reg;
    CVMX_MT_3DES_IV(iv[0]);

    CVMX_PREFETCH0(inp64);

    i0 = *inp64;

    /* DES3 assembly can handle 16-byte chunks */
    if (inl >= 16) {
        CVMX_MT_3DES_DEC_CBC(i0);
        inl -= 8;
        inp64++;
        outp64++;

        if (inl >= 8) {
            i0 = inp64[0];
            CVMX_MF_3DES_RESULT(r0);
            CVMX_MT_3DES_DEC_CBC(i0);

            for (;;) {
                outp64[-1] = r0;
                inl -= 8;
                inp64++;
                outp64++;
                i0 = *inp64;

                if (inl < 8)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_3DES_RESULT(r0);
                CVMX_MT_3DES_DEC_CBC(i0);
            }
        }

        CVMX_MF_3DES_RESULT(r0);
        outp64[-1] = r0;
    }
    /* remainder */
    if (inl > 0) {
        if (inl <= 8) {
            uint64_t r = 0;
            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_DEC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
        else {
            uint64_t r = 0;
            i0 = *inp64;
            CVMX_MT_3DES_DEC_CBC(i0);
            CVMX_MF_3DES_RESULT(*outp64);
            inp64++, outp64++;

            XMEMCPY(&r, inp64, inl);
            CVMX_MT_3DES_DEC_CBC(r);
            CVMX_MF_3DES_RESULT(*outp64);
        }
    }

    CVMX_MT_3DES_IV(iv[0]);

    return 0;
}
#endif /* !NO_DES3 */


#ifndef NO_AES

#ifdef HAVE_AES_CBC
static int Octeon_AesCbc_Encrypt(Aes *aes,
        uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, i1, r0, r1;
    uint64_t *key, *iv;

    if (aes == NULL || inp64 == NULL || outp64 == NULL) {
        return BAD_FUNC_ARG;
    }

    iv = (uint64_t*)aes->reg;
    CVMX_MT_AES_IV(iv[0], 0);
    CVMX_MT_AES_IV(iv[1], 1);

    key = (uint64_t*)aes->devKey;
    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);

    CVMX_MT_AES_KEYLENGTH(aes->keylen/8 - 1);

    CVMX_PREFETCH0(inp64);

    i0 = inp64[0];
    i1 = inp64[1];

    /* AES assembly can handle 32-byte chunks */
    if (inl >= 32) {
        CVMX_MT_AES_ENC_CBC0(i0);
        CVMX_MT_AES_ENC_CBC1(i1);
        inl -= 16;
        inp64  += 2;
        outp64 += 2;

        if (inl >= 16) {
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            i0 = inp64[0];
            i1 = inp64[1];
            CVMX_MT_AES_ENC_CBC0(i0);
            CVMX_MT_AES_ENC_CBC1(i1);

            for (;;) {
                outp64[-2] = r0;
                outp64[-1] = r1;
                outp64 += 2;
                inp64 += 2;
                inl -= 16;
                i0 = inp64[0];
                i1 = inp64[1];

                if (inl < 16)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                CVMX_MT_AES_ENC_CBC0(i0);
                CVMX_MT_AES_ENC_CBC1(i1);
            }
        }

        CVMX_MF_AES_RESULT(r0, 0);
        CVMX_MF_AES_RESULT(r1, 1);
        outp64[-2] = r0;
        outp64[-1] = r1;
    }
    /* remainder */
    if (inl > 0) {
        uint64_t in64[2] = { 0, 0 };
        if (inl <= 16) {
            XMEMCPY(in64, inp64, inl);
            CVMX_MT_AES_ENC_CBC0(in64[0]);
            CVMX_MT_AES_ENC_CBC1(in64[1]);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[0] = r0;
            outp64[1] = r1;
        }
        else {
            CVMX_MT_AES_ENC_CBC0(i0);
            CVMX_MT_AES_ENC_CBC1(i1);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            inl -= 16;
            outp64[0] = r0;
            outp64[1] = r1;
            inp64 += 2;
            outp64 += 2;
            XMEMCPY(in64, inp64, inl);
            CVMX_MT_AES_ENC_CBC0(in64[0]);
            CVMX_MT_AES_ENC_CBC1(in64[1]);
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            outp64[0] = r0;
            outp64[1] = r1;
        }
    }

    CVMX_MF_AES_IV(iv[0], 0);
    CVMX_MF_AES_IV(iv[1], 1);

    return 0;
}

static int Octeon_AesCbc_Decrypt(Aes *aes,
        uint64_t *inp64, uint64_t *outp64, size_t inl)
{
    register uint64_t i0, i1, r0, r1;
    uint64_t *key, *iv;

    if (aes == NULL || inp64 == NULL || outp64 == NULL) {
        return BAD_FUNC_ARG;
    }

    iv = (uint64_t*)aes->reg;
    key = (uint64_t*)aes->devKey;

    CVMX_MT_AES_IV(iv[0], 0);
    CVMX_MT_AES_IV(iv[1], 1);

    CVMX_MT_AES_KEY(key[0], 0);
    CVMX_MT_AES_KEY(key[1], 1);
    CVMX_MT_AES_KEY(key[2], 2);
    CVMX_MT_AES_KEY(key[3], 3);
    CVMX_MT_AES_KEYLENGTH(aes->keylen/8 - 1);

    CVMX_PREFETCH0(inp64);

    i0 = inp64[0];
    i1 = inp64[1];

    /* AES assembly can handle 32-byte chunks */
    if (inl >= 32) {
        CVMX_MT_AES_DEC_CBC0(i0);
        CVMX_MT_AES_DEC_CBC1(i1);
        inp64 += 2;
        outp64 += 2;
        inl -= 16;

        if (inl >= 16) {
            i0 = inp64[0];
            i1 = inp64[1];
            CVMX_MF_AES_RESULT(r0, 0);
            CVMX_MF_AES_RESULT(r1, 1);
            CVMX_MT_AES_DEC_CBC0(i0);
            CVMX_MT_AES_DEC_CBC1(i1);

            for (;;) {
                outp64[-2] = r0;
                outp64[-1] = r1;
                outp64 += 2;
                inp64 += 2;
                inl -= 16;
                i0 = inp64[0];
                i1 = inp64[1];

                if (inl < 16)
                    break;

                CVMX_PREFETCH(inp64, 64);
                CVMX_MF_AES_RESULT(r0, 0);
                CVMX_MF_AES_RESULT(r1, 1);
                CVMX_MT_AES_DEC_CBC0(i0);
                CVMX_MT_AES_DEC_CBC1(i1);
           }
        }

        CVMX_MF_AES_RESULT(r0, 0);
        CVMX_MF_AES_RESULT(r1, 1);
        outp64[-2] = r0;
        outp64[-1] = r1;
    }
    /* remainder */
    if (inl > 0) {
        uint64_t in64[2] = { 0, 0 };
        XMEMCPY(in64, inp64, inl);
        CVMX_MT_AES_DEC_CBC0(in64[0]);
        CVMX_MT_AES_DEC_CBC1(in64[1]);
        CVMX_MF_AES_RESULT(r0, 0);
        CVMX_MF_AES_RESULT(r1, 1);
        outp64[0] = r0;
        outp64[1] = r1;
    }

    CVMX_MF_AES_IV(iv[0], 0);
    CVMX_MF_AES_IV(iv[1], 1);

    return 0;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM

#define CVM_AES_RD_RESULT_WR_DATA(in1, in2, out1, out2) \
    asm volatile(\
            ".set noreorder    \n" \
            "dmfc2 %[r1],0x0100\n" \
            "dmfc2 %[r2],0x0101\n" \
            "dmtc2 %[r3],0x010a\n" \
            "dmtc2 %[r4],0x310b\n" \
            ".set reorder      \n" \
            : [r1] "=&d"(in1) , [r2] "=&d"(in2) \
            : [r3] "d"(out1),  [r4] "d"(out2))

static NOOPT void Octeon_GHASH_Restore(word16 poly, byte* h)
{
    word64* bigH = (word64*)h;
    CVMX_MT_GFM_POLY((word64)poly);
    CVMX_MT_GFM_MUL(bigH[0], 0);
    CVMX_MT_GFM_MUL(bigH[1], 1);
}


static NOOPT void Octeon_GHASH_Init(word16 poly, byte* h)
{
    Octeon_GHASH_Restore(poly, h);
    CVMX_MT_GFM_RESINP(0, 0);
    CVMX_MT_GFM_RESINP(0, 1);
}


static NOOPT void Octeon_GHASH_Update(byte* in)
{
    word64* bigIn = (word64*)in;
    CVMX_MT_GFM_XOR0(bigIn[0]);
    CVMX_MT_GFM_XORMUL1(bigIn[1]);
}


static NOOPT void Octeon_GHASH_Final(byte* out, word64 authInSz, word64 inSz)
{
    word64* bigOut = (word64*)out;

    CVMX_MT_GFM_XOR0(authInSz * 8);
    CVMX_MT_GFM_XORMUL1(inSz * 8);
    CVMX_MF_GFM_RESINP(bigOut[0], 0);
    CVMX_MF_GFM_RESINP(bigOut[1], 1);
}


/* Sets the Octeon key with the key found in the Aes record. */
static NOOPT int Octeon_AesGcm_SetKey(Aes* aes)
{
    int ret = 0;

    if (aes == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        uint64_t* key = (uint64_t*)aes->devKey;

        CVMX_MT_AES_KEY(key[0], 0);
        CVMX_MT_AES_KEY(key[1], 1);
        CVMX_MT_AES_KEY(key[2], 2);
        CVMX_MT_AES_KEY(key[3], 3);
        CVMX_MT_AES_KEYLENGTH((aes->keylen / 8) - 1);

        if (!aes->keySet) {
            uint64_t* bigH = (uint64_t*)aes->H;
            CVMX_MT_AES_ENC0(0);
            CVMX_MT_AES_ENC1(0);
            CVMX_MF_AES_RESULT(bigH[0], 0);
            CVMX_MF_AES_RESULT(bigH[1], 1);
            aes->keySet = 1;
        }
    }

    return ret;
}


static NOOPT int Octeon_AesGcm_SetIV(Aes* aes, byte* iv, word32 ivSz)
{
    int ret = 0;

    if (aes == NULL || iv == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        if (ivSz == GCM_NONCE_MID_SZ) {
            XMEMSET((byte*)aes->reg, 0, sizeof(aes->reg));
            XMEMCPY((byte*)aes->reg, iv, ivSz);
            aes->reg[3] = 1;
        }
        else {
            int blocks, remainder, i;
            byte aesBlock[AES_BLOCK_SIZE];

            blocks = ivSz / AES_BLOCK_SIZE;
            remainder = ivSz % AES_BLOCK_SIZE;

            for (i = 0; i < blocks; i++, iv += AES_BLOCK_SIZE)
                Octeon_GHASH_Update(iv);

            XMEMSET(aesBlock, 0, sizeof(aesBlock));
            for (i = 0; i < remainder; i++)
                aesBlock[i] = iv[i];
            Octeon_GHASH_Update(aesBlock);

            Octeon_GHASH_Final((byte*)aes->reg, 0, ivSz);
        }

        aes->y0 = aes->reg[3];
        aes->reg[3]++;

        Octeon_GHASH_Init(0xe100, aes->H);
    }

    return ret;
}


static NOOPT int Octeon_AesGcm_SetAAD(Aes* aes, byte* aad, word32 aadSz)
{
    word64* p;
    ALIGN16 byte aesBlock[AES_BLOCK_SIZE];
    int blocks, remainder, i;

    if (aes == NULL || (aadSz != 0 && aad == NULL))
        return BAD_FUNC_ARG;

    if (aadSz == 0)
        return 0;

    blocks = aadSz / AES_BLOCK_SIZE;
    remainder = aadSz % AES_BLOCK_SIZE;

    Octeon_GHASH_Restore(0xe100, aes->H);

    p = (word64*)aesBlock;

    for (i = 0; i < blocks; i++, aad += AES_BLOCK_SIZE) {
        CVMX_LOADUNA_INT64(p[0], aad, 0);
        CVMX_LOADUNA_INT64(p[1], aad, 8);
        CVMX_MT_GFM_XOR0(p[0]);
        CVMX_MT_GFM_XORMUL1(p[1]);
    }

    XMEMSET(aesBlock, 0, sizeof(aesBlock));

    for (i = 0; i < remainder; i++)
        aesBlock[i] = aad[i];

    CVMX_MT_GFM_XOR0(p[0]);
    CVMX_MT_GFM_XORMUL1(p[1]);

    return 0;
}


static int Octeon_AesGcm_SetEncrypt(Aes* aes, byte* in, byte* out, word32 inSz,
        int encrypt)
{
    word32 i, blocks, remainder;
    ALIGN16 byte aesBlockIn[AES_BLOCK_SIZE];
    ALIGN16 byte aesBlockOut[AES_BLOCK_SIZE];
    word64* pIn;
    word64* pOut;
    word64* pIv;

    if (aes == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    pIn = (word64*)aesBlockIn;
    pOut = (word64*)aesBlockOut;
    pIv = (word64*)aes->reg;

    CVMX_PREFETCH0(in);

    CVMX_MT_AES_ENC0(pIv[0]);
    CVMX_MT_AES_ENC1(pIv[1]);

    blocks = inSz / AES_BLOCK_SIZE;
    remainder = inSz % AES_BLOCK_SIZE;

    for (i = 0; i < blocks;
            i++, in += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE) {
        CVMX_PREFETCH128(in);
        aes->reg[3]++;

        CVMX_LOADUNA_INT64(pIn[0], in, 0);
        CVMX_LOADUNA_INT64(pIn[1], in, 8);

        CVM_AES_RD_RESULT_WR_DATA(pOut[0], pOut[1], pIv[0], pIv[1]);

        if (encrypt) {
            pOut[0] ^= pIn[0];
            pOut[1] ^= pIn[1];
            CVMX_MT_GFM_XOR0(pOut[0]);
            CVMX_MT_GFM_XORMUL1(pOut[1]);
        }
        else {
            CVMX_MT_GFM_XOR0(pIn[0]);
            CVMX_MT_GFM_XORMUL1(pIn[1]);
            pOut[0] ^= pIn[0];
            pOut[1] ^= pIn[1];
        }

        CVMX_STOREUNA_INT64(pOut[0], out, 0);
        CVMX_STOREUNA_INT64(pOut[1], out, 8);
    }

    if (remainder > 0) {
        ALIGN16 byte aesBlockMask[AES_BLOCK_SIZE];
        word64* pMask = (word64*)aesBlockMask;

        XMEMSET(aesBlockOut, 0, sizeof(aesBlockOut));
        XMEMSET(aesBlockMask, 0, sizeof(aesBlockMask));
        for (i = 0; i < remainder; i++) {
            aesBlockIn[i] = in[i];
            aesBlockMask[i] = 0xFF;
        }

        if (encrypt) {
            CVMX_MF_AES_RESULT(pOut[0], 0);
            CVMX_MF_AES_RESULT(pOut[1], 1);

            pOut[0] ^= pIn[0];
            pOut[1] ^= pIn[1];

            pOut[0] &= pMask[0];
            pOut[1] &= pMask[1];

            CVMX_MT_GFM_XOR0(pOut[0]);
            CVMX_MT_GFM_XORMUL1(pOut[1]);
        }
        else {
            CVMX_MT_GFM_XOR0(pIn[0]);
            CVMX_MT_GFM_XORMUL1(pIn[1]);

            CVMX_MF_AES_RESULT(pOut[0], 0);
            CVMX_MF_AES_RESULT(pOut[1], 1);

            pOut[0] ^= pIn[0];
            pOut[1] ^= pIn[1];

            pOut[0] &= pMask[0];
            pOut[1] &= pMask[1];
        }

        for (i = 0; i < remainder; i++)
            out[i] = aesBlockOut[i];
    }

    return 0;
}


static NOOPT int Octeon_AesGcm_Finalize(Aes* aes, word32 inSz, word32 aadSz,
        byte* tag)
{
    word64 bigSz;
    word64* pIv;
    word64* pIn;
    word64* pOut;
    uint32_t countSave;
    ALIGN16 byte aesBlockIn[AES_BLOCK_SIZE];
    ALIGN16 byte aesBlockOut[AES_BLOCK_SIZE];

    countSave = aes->reg[3];
    aes->reg[3] = aes->y0;

    pIv = (word64*)aes->reg;
    CVMX_MT_AES_ENC0(pIv[0]);
    CVMX_MT_AES_ENC1(pIv[1]);

    bigSz = (word64)aadSz * 8;
    CVMX_MT_GFM_XOR0(bigSz);
    bigSz = (word64)inSz * 8;
    CVMX_MT_GFM_XORMUL1(bigSz);

    aes->reg[3] = countSave;

    pIn = (word64*)aesBlockIn;
    CVMX_MF_AES_RESULT(pIn[0], 0);
    CVMX_MF_AES_RESULT(pIn[1], 1);

    pOut = (word64*)aesBlockOut;
    CVMX_MF_GFM_RESINP(pOut[0], 0);
    CVMX_MF_GFM_RESINP(pOut[1], 1);

    pOut[0] ^= pIn[0];
    pOut[1] ^= pIn[1];

    CVMX_STOREUNA_INT64(pOut[0], tag, 0);
    CVMX_STOREUNA_INT64(pOut[1], tag, 8);

    return 0;
}


static int Octeon_AesGcm_Encrypt(Aes* aes, byte* in, byte* out, word32 inSz,
        byte* iv, word32 ivSz, byte* aad, word32 aadSz, byte* tag)
{
    int ret = 0;

    if (aes == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == 0)
        ret = Octeon_AesGcm_SetKey(aes);

    if (ret == 0)
        ret = Octeon_AesGcm_SetIV(aes, iv, ivSz);

    if (ret == 0)
        ret = Octeon_AesGcm_SetAAD(aes, aad, aadSz);

    if (ret == 0)
        ret = Octeon_AesGcm_SetEncrypt(aes, in, out, inSz, 1);

    if (ret == 0)
        ret = Octeon_AesGcm_Finalize(aes, inSz, aadSz, tag);

    return ret;
}


static int Octeon_AesGcm_Decrypt(Aes* aes, byte* in, byte* out, word32 inSz,
        byte* iv, word32 ivSz, byte* aad, word32 aadSz, byte* tag)
{
    int ret = 0;

    if (aes == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == 0)
        ret = Octeon_AesGcm_SetKey(aes);

    if (ret == 0)
        ret = Octeon_AesGcm_SetIV(aes, iv, ivSz);

    if (ret == 0)
        ret = Octeon_AesGcm_SetAAD(aes, aad, aadSz);

    if (ret == 0)
        ret = Octeon_AesGcm_SetEncrypt(aes, in, out, inSz, 0);

    if (ret == 0)
        ret = Octeon_AesGcm_Finalize(aes, inSz, aadSz, tag);

    return ret;
}

#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#ifdef WOLF_CRYPTO_CB

#include <wolfssl/wolfcrypt/cryptocb.h>


static int myCryptoDevCb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    int ret = NOT_COMPILED_IN; /* return this to bypass HW and use SW */

    if (info == NULL)
        return BAD_FUNC_ARG;

#ifdef DEBUG_WOLFSSL
    printf("CryptoDevCb: Algo Type %d\n", info->algo_type);
#endif

    if (info->algo_type == WC_ALGO_TYPE_HASH) {
#if !defined(NO_SHA)
        if (info->hash.type == WC_HASH_TYPE_SHA) {
            ret = Octeon_Sha_Hash(
                info->hash.sha1,
                (byte*)info->hash.in,
                info->hash.inSz,
                info->hash.digest
            );
        }
#endif
#if !defined(NO_SHA256)
        if (info->hash.type == WC_HASH_TYPE_SHA256) {
            ret = Octeon_Sha256_Hash(
                info->hash.sha256,
                (byte*)info->hash.in,
                info->hash.inSz,
                info->hash.digest
            );
        }
#endif
    }
    if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
#if !defined(NO_AES) || !defined(NO_DES3)
    #ifdef HAVE_AESGCM
        if (info->cipher.type == WC_CIPHER_AES_GCM) {
            return NOT_COMPILED_IN;
            if (info->cipher.enc) {
                ret = Octeon_AesGcm_Encrypt(
                    info->cipher.aesgcm_enc.aes,
                    (byte*)info->cipher.aesgcm_enc.in,
                    (byte*)info->cipher.aesgcm_enc.out,
                    info->cipher.aesgcm_enc.sz,
                    (byte*)info->cipher.aesgcm_enc.iv,
                    info->cipher.aesgcm_enc.ivSz,
                    (byte*)info->cipher.aesgcm_enc.authIn,
                    info->cipher.aesgcm_enc.authInSz,
                    (byte*)info->cipher.aesgcm_enc.authTag);
            }
            else {
                ret = Octeon_AesGcm_Decrypt(
                    info->cipher.aesgcm_dec.aes,
                    (byte*)info->cipher.aesgcm_dec.in,
                    (byte*)info->cipher.aesgcm_dec.out,
                    info->cipher.aesgcm_dec.sz,
                    (byte*)info->cipher.aesgcm_dec.iv,
                    info->cipher.aesgcm_dec.ivSz,
                    (byte*)info->cipher.aesgcm_dec.authIn,
                    info->cipher.aesgcm_dec.authInSz,
                    (byte*)info->cipher.aesgcm_dec.authTag);
            }
        }
    #endif /* HAVE_AESGCM */
    #ifdef HAVE_AES_CBC
        if (info->cipher.type == WC_CIPHER_AES_CBC) {
            if (info->cipher.enc) {
                ret = Octeon_AesCbc_Encrypt(
                    info->cipher.aescbc.aes,
                    (word64*)info->cipher.aescbc.in,
                    (word64*)info->cipher.aescbc.out,
                    info->cipher.aescbc.sz);
            }
            else {
                ret = Octeon_AesCbc_Decrypt(
                    info->cipher.aescbc.aes,
                    (word64*)info->cipher.aescbc.in,
                    (word64*)info->cipher.aescbc.out,
                    info->cipher.aescbc.sz);
            }
        }
    #endif /* HAVE_AES_CBC */
    #ifndef NO_DES3
        if (info->cipher.type == WC_CIPHER_DES3) {
            if (info->cipher.enc) {
                ret = Octeon_Des3_CbcEncrypt(
                    info->cipher.des3.des,
                    (word64*)info->cipher.des3.in,
                    (word64*)info->cipher.des3.out,
                    info->cipher.des3.sz);
            }
            else {
                ret = Octeon_Des3_CbcDecrypt(
                    info->cipher.des3.des,
                    (word64*)info->cipher.des3.in,
                    (word64*)info->cipher.des3.out,
                    info->cipher.des3.sz);
            }
        }
    #endif /* !NO_DES3 */
#endif /* !NO_AES || !NO_DES3 */
    }

    (void)devIdArg;
    (void)ctx;

    return ret;
}

int wc_CryptoCb_InitOcteon(void)
{
    if (wc_CryptoCb_RegisterDevice(devId, myCryptoDevCb, NULL) < 0) {
        return INVALID_DEVID;
    }

    return devId;
}

void wc_CryptoCb_CleanupOcteon(int* id)
{
    wc_CryptoCb_UnRegisterDevice(*id);
    *id = INVALID_DEVID;
}

#endif /* WOLF_CRYPTO_CB */

#endif /* HAVE_CAVIUM_OCTEON_SYNC */
