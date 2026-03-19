/* puf.c
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


#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_PUF

#ifndef HAVE_FIPS

#include <wolfssl/wolfcrypt/puf.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef HAVE_HKDF
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ========================================================================== */
/* BCH(127,64,t=10) codec over GF(2^7)                                       */
/* ========================================================================== */

/* GF(2^7) arithmetic with primitive polynomial p(x) = x^7 + x^3 + 1 (0x89) */
#define GF_M      7
#define GF_SIZE   (1 << GF_M)   /* 128 */
#define GF_MASK   (GF_SIZE - 1) /* 127 */
#define GF_POLY   0x89          /* x^7 + x^3 + 1 */

/* Log and exp tables for GF(2^7) */
static byte gf_exp[GF_SIZE];  /* exp table: alpha^i */
static byte gf_log[GF_SIZE];  /* log table: log_alpha(x) */
static int  gf_tables_init = 0;

/* Initialize GF(2^7) log/exp tables */
static void gf_init(void)
{
    int i;
    int x = 1;

    if (gf_tables_init)
        return;

    for (i = 0; i < GF_MASK; i++) {
        gf_exp[i] = (byte)x;
        gf_log[x] = (byte)i;
        x <<= 1;
        if (x & GF_SIZE)
            x ^= GF_POLY;
    }
    gf_exp[GF_MASK] = gf_exp[0]; /* wrap around */
    gf_log[0] = 0; /* undefined, but set to 0 for safety */

    gf_tables_init = 1;
}

/* GF multiplication */
static WC_INLINE byte gf_mul(byte a, byte b)
{
    if (a == 0 || b == 0)
        return 0;
    return gf_exp[(gf_log[a] + gf_log[b]) % GF_MASK];
}

/* GF inverse */
static WC_INLINE byte gf_inv(byte a)
{
    if (a == 0)
        return 0;
    return gf_exp[GF_MASK - gf_log[a]];
}

/* ---- BCH syndrome computation ---- */

/* Evaluate bit-polynomial at alpha^i: sum of bits where bit j contributes
 * alpha^(i*j). Input is 127 bits packed in 16 bytes (MSB first). */
static byte bch_syndrome_eval(const byte* codeword, int root)
{
    byte s = 0;
    int j;

    for (j = 0; j < WC_PUF_BCH_N; j++) {
        int byteIdx = j / 8;
        int bitIdx  = 7 - (j % 8);

        if (codeword[byteIdx] & (1 << bitIdx)) {
            /* add alpha^(root*j) */
            s ^= gf_exp[(root * j) % GF_MASK];
        }
    }
    return s;
}

/* Compute 2t syndromes S[1..2t] */
static void bch_syndromes(const byte* codeword, byte* syndromes)
{
    int i;
    for (i = 1; i <= 2 * WC_PUF_BCH_T; i++) {
        syndromes[i] = bch_syndrome_eval(codeword, i);
    }
}

/* ---- Berlekamp-Massey algorithm ---- */

/* Find error locator polynomial sigma(x) from syndromes.
 * sigma[] has degree <= t, coefficients in GF(2^7).
 * Returns degree of sigma, or -1 on failure. */
static int bch_berlekamp_massey(const byte* syndromes, byte* sigma)
{
    byte C[WC_PUF_BCH_T + 1];  /* current polynomial */
    byte B[WC_PUF_BCH_T + 1];  /* previous polynomial */
    byte T[WC_PUF_BCH_T + 1];  /* temp */
    int L = 0;                  /* current length */
    int m = 1;                  /* shift counter */
    byte b = 1;                 /* previous discrepancy */
    int n, i, degC;

    XMEMSET(C, 0, sizeof(C));
    XMEMSET(B, 0, sizeof(B));
    C[0] = 1;
    B[0] = 1;

    for (n = 0; n < 2 * WC_PUF_BCH_T; n++) {
        /* compute discrepancy d */
        byte d = syndromes[n + 1];
        for (i = 1; i <= L; i++) {
            d ^= gf_mul(C[i], syndromes[n + 1 - i]);
        }

        if (d == 0) {
            m++;
        }
        else if (2 * L <= n) {
            /* update: T(x) = C(x), C(x) -= (d/b)*x^m * B(x), B=T, L=n+1-L */
            byte coeff = gf_mul(d, gf_inv(b));
            XMEMCPY(T, C, sizeof(T));
            for (i = m; i <= WC_PUF_BCH_T; i++) {
                C[i] ^= gf_mul(coeff, B[i - m]);
            }
            XMEMCPY(B, T, sizeof(B));
            L = n + 1 - L;
            b = d;
            m = 1;
        }
        else {
            /* C(x) -= (d/b)*x^m * B(x) */
            byte coeff = gf_mul(d, gf_inv(b));
            for (i = m; i <= WC_PUF_BCH_T; i++) {
                C[i] ^= gf_mul(coeff, B[i - m]);
            }
            m++;
        }
    }

    XMEMCPY(sigma, C, (WC_PUF_BCH_T + 1));

    /* find degree */
    degC = 0;
    for (i = WC_PUF_BCH_T; i >= 0; i--) {
        if (sigma[i] != 0) {
            degC = i;
            break;
        }
    }

    if (degC > WC_PUF_BCH_T)
        return -1;

    return degC;
}

/* ---- Chien search: find error locations ---- */

/* Evaluate sigma at alpha^(-j) for j=0..126. Returns number of roots found.
 * Error positions stored in errPos[]. */
static int bch_chien_search(const byte* sigma, int deg, int* errPos)
{
    int count = 0;
    int j;

    for (j = 0; j < WC_PUF_BCH_N; j++) {
        byte val = 0;
        int i;
        for (i = 0; i <= deg; i++) {
            if (sigma[i] != 0) {
                /* sigma[i] * alpha^(-i*j) */
                int exp_val = (GF_MASK - ((i * j) % GF_MASK)) % GF_MASK;
                val ^= gf_mul(sigma[i], gf_exp[exp_val]);
            }
        }
        if (val == 0) {
            errPos[count] = j;
            count++;
        }
    }

    return count;
}

/* ---- BCH encode: compute parity for 64-bit message ---- */

/* Generator polynomial for BCH(127,64,t=10) over GF(2).
 * This is the product of minimal polynomials of alpha^1..alpha^(2t).
 * Degree = n - k = 63. Stored as 64-bit value (coefficients mod 2).
 * g(x) = GCD of min polys of consecutive roots. Precomputed. */

/* We store g(x) as 8 bytes, MSB first, degree-63 coefficient in bit 63.
 * The leading coefficient (x^63) is implicit. */
static const byte bch_genpoly[8] = {
    0xE4, 0x26, 0xC1, 0xC9, 0x8A, 0xF2, 0x5B, 0x47
};

/* Encode 64-bit message into 127-bit codeword.
 * msg: 8 bytes (64 bits), output: 16 bytes (127 bits, MSB aligned).
 * Systematic encoding: codeword = [msg(64) | parity(63)]. */
static void bch_encode(const byte* msg, byte* codeword)
{
    byte shift_reg[8]; /* 63-bit shift register for parity */
    int i, j;

    XMEMSET(shift_reg, 0, sizeof(shift_reg));

    /* Process each of the 64 message bits */
    for (i = 0; i < WC_PUF_BCH_K; i++) {
        int byteIdx = i / 8;
        int bitIdx  = 7 - (i % 8);
        byte msgBit = (msg[byteIdx] >> bitIdx) & 1;

        /* feedback = msgBit XOR MSB of shift register */
        byte fb = msgBit ^ ((shift_reg[0] >> 6) & 1);

        /* shift register left by 1 */
        for (j = 0; j < 7; j++) {
            shift_reg[j] = (byte)((shift_reg[j] << 1) |
                                  (shift_reg[j + 1] >> 7));
        }
        shift_reg[7] = (byte)(shift_reg[7] << 1);

        /* XOR with generator if feedback is 1 */
        if (fb) {
            for (j = 0; j < 8; j++) {
                shift_reg[j] ^= bch_genpoly[j];
            }
        }
    }

    /* Build codeword: [msg(64 bits) | parity(63 bits)] = 127 bits */
    XMEMSET(codeword, 0, 16);
    XMEMCPY(codeword, msg, 8);  /* message in first 64 bits */

    /* parity: bits 64..126 from shift_reg bits 0..62 */
    /* shift_reg holds 63 bits in bits [6..0] of byte 0, then bytes 1..7 */
    /* We need to place these starting at bit position 64 in codeword */
    for (i = 0; i < 63; i++) {
        int srcByte = i / 8;
        int srcBit  = 6 - (i % 8);

        /* Adjust: shift_reg MSB is bit 6 of byte 0 */
        if (i < 7) {
            srcByte = 0;
            srcBit = 6 - i;
        }
        else {
            srcByte = (i - 7) / 8 + 1;
            srcBit = 7 - ((i - 7) % 8);
        }

        if (shift_reg[srcByte] & (1 << srcBit)) {
            int dstPos = 64 + i;
            int dstByte = dstPos / 8;
            int dstBit  = 7 - (dstPos % 8);
            codeword[dstByte] |= (byte)(1 << dstBit);
        }
    }
}

/* ---- BCH decode ---- */

/* Decode 127-bit codeword, correct up to t=10 errors.
 * Extracts 64-bit message into msg (8 bytes).
 * Returns 0 on success, negative on uncorrectable error. */
static int bch_decode(byte* codeword, byte* msg)
{
    byte syndr[2 * WC_PUF_BCH_T + 1];
    byte sigma[WC_PUF_BCH_T + 1];
    int errPos[WC_PUF_BCH_T];
    int deg, numErr;
    int i;
    int allZero = 1;

    bch_syndromes(codeword, syndr);

    /* check if all syndromes are zero (no errors) */
    for (i = 1; i <= 2 * WC_PUF_BCH_T; i++) {
        if (syndr[i] != 0) {
            allZero = 0;
            break;
        }
    }

    if (allZero) {
        /* no errors, extract message directly */
        XMEMCPY(msg, codeword, 8);
        return 0;
    }

    deg = bch_berlekamp_massey(syndr, sigma);
    if (deg < 0)
        return PUF_RECONSTRUCT_E;

    numErr = bch_chien_search(sigma, deg, errPos);
    if (numErr != deg)
        return PUF_RECONSTRUCT_E;  /* number of roots must match degree */

    /* correct errors by flipping bits */
    for (i = 0; i < numErr; i++) {
        int pos = errPos[i];
        if (pos < WC_PUF_BCH_N) {
            int byteIdx = pos / 8;
            int bitIdx  = 7 - (pos % 8);
            codeword[byteIdx] ^= (byte)(1 << bitIdx);
        }
    }

    /* extract message (first 64 bits) */
    XMEMCPY(msg, codeword, 8);
    return 0;
}

/* ========================================================================== */
/* PUF API                                                                    */
/* ========================================================================== */

/* Get a single bit from byte array (MSB-first bit ordering) */
static WC_INLINE byte getBit(const byte* data, int bitPos)
{
    return (data[bitPos / 8] >> (7 - (bitPos % 8))) & 1;
}

/* Set a single bit in byte array (MSB-first bit ordering) */
static WC_INLINE void setBit(byte* data, int bitPos, byte val)
{
    int byteIdx = bitPos / 8;
    int bitIdx  = 7 - (bitPos % 8);
    if (val)
        data[byteIdx] |= (byte)(1 << bitIdx);
    else
        data[byteIdx] &= (byte)~(1 << bitIdx);
}

/* Extract 127 bits from raw SRAM starting at given bit offset */
static void extractCodeword(const byte* sram, int bitOffset, byte* cw)
{
    int i;
    XMEMSET(cw, 0, 16);
    for (i = 0; i < WC_PUF_BCH_N; i++) {
        setBit(cw, i, getBit(sram, bitOffset + i));
    }
}

/* Store 127 bits into helper data at given bit offset */
static void storeCodeword(byte* helper, int bitOffset, const byte* cw)
{
    int i;
    for (i = 0; i < WC_PUF_BCH_N; i++) {
        setBit(helper, bitOffset + i, getBit(cw, i));
    }
}


int wc_PufInit(PufCtx* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(ctx, 0, sizeof(PufCtx));
    gf_init();

    return 0;
}

int wc_PufReadSram(PufCtx* ctx, const byte* sramAddr, word32 sramSz)
{
    if (ctx == NULL || sramAddr == NULL)
        return BAD_FUNC_ARG;
    if (sramSz < WC_PUF_RAW_BYTES)
        return PUF_READ_E;

#ifdef WOLFSSL_PUF_TEST
    if (ctx->testSram != NULL) {
        word32 copySz = (ctx->testSramSz < WC_PUF_RAW_BYTES) ?
                         ctx->testSramSz : WC_PUF_RAW_BYTES;
        XMEMCPY(ctx->rawSram, ctx->testSram, copySz);
        return 0;
    }
#endif

    XMEMCPY(ctx->rawSram, sramAddr, WC_PUF_RAW_BYTES);
    return 0;
}

int wc_PufEnroll(PufCtx* ctx)
{
    int i, ret;

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(ctx->helperData, 0, WC_PUF_HELPER_BYTES);
    XMEMSET(ctx->stableBits, 0, WC_PUF_STABLE_BYTES);

    for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
        byte msg[8];    /* 64-bit message */
        byte cw[16];    /* 127-bit codeword */

        /* extract 64 message bits from raw SRAM */
        int bitOff = i * 128;  /* 128-bit stride for alignment */
        int j;
        XMEMSET(msg, 0, sizeof(msg));
        for (j = 0; j < WC_PUF_BCH_K; j++) {
            setBit(msg, j, getBit(ctx->rawSram, bitOff + j));
        }

        /* save stable bits */
        XMEMCPY(ctx->stableBits + i * 8, msg, 8);

        /* encode message into BCH codeword */
        bch_encode(msg, cw);

        /* helper = raw XOR codeword (mask) */
        {
            byte rawCw[16];
            byte helperCw[16];
            extractCodeword(ctx->rawSram, bitOff, rawCw);
            XMEMSET(helperCw, 0, 16);
            for (j = 0; j < 16; j++) {
                helperCw[j] = rawCw[j] ^ cw[j];
            }
            storeCodeword(ctx->helperData, i * WC_PUF_BCH_N, helperCw);
        }
    }

    /* compute identity = SHA-256(stableBits) */
    ret = wc_Sha256Hash(ctx->stableBits, WC_PUF_STABLE_BYTES, ctx->identity);
    if (ret != 0)
        return PUF_ENROLL_E;

    ctx->flags |= WC_PUF_FLAG_ENROLLED | WC_PUF_FLAG_READY;
    return 0;
}

int wc_PufReconstruct(PufCtx* ctx, const byte* helperData, word32 helperSz)
{
    int i, ret;

    if (ctx == NULL || helperData == NULL)
        return BAD_FUNC_ARG;
    if (helperSz < WC_PUF_HELPER_BYTES)
        return PUF_RECONSTRUCT_E;

    XMEMSET(ctx->stableBits, 0, WC_PUF_STABLE_BYTES);

    for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
        byte rawCw[16];
        byte helperCw[16];
        byte noisyCw[16];
        byte msg[8];
        int bitOff = i * 128;
        int j;

        /* get raw SRAM bits for this codeword */
        extractCodeword(ctx->rawSram, bitOff, rawCw);

        /* get helper data for this codeword */
        XMEMSET(helperCw, 0, 16);
        for (j = 0; j < WC_PUF_BCH_N; j++) {
            setBit(helperCw, j, getBit(helperData, i * WC_PUF_BCH_N + j));
        }

        /* noisy codeword = raw XOR helper */
        for (j = 0; j < 16; j++) {
            noisyCw[j] = rawCw[j] ^ helperCw[j];
        }

        /* BCH decode to recover original message */
        ret = bch_decode(noisyCw, msg);
        if (ret != 0)
            return PUF_RECONSTRUCT_E;

        XMEMCPY(ctx->stableBits + i * 8, msg, 8);
    }

    /* compute identity */
    ret = wc_Sha256Hash(ctx->stableBits, WC_PUF_STABLE_BYTES, ctx->identity);
    if (ret != 0)
        return PUF_RECONSTRUCT_E;

    ctx->flags |= WC_PUF_FLAG_READY;
    return 0;
}

int wc_PufDeriveKey(PufCtx* ctx, const byte* info, word32 infoSz,
                    byte* key, word32 keySz)
{
    if (ctx == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_READY))
        return PUF_DERIVE_KEY_E;
    if (keySz == 0)
        return BAD_FUNC_ARG;

#ifdef HAVE_HKDF
    {
        /* HKDF with stable bits as IKM, identity as salt */
        int ret;
        ret = wc_HKDF(WC_SHA256,
                       ctx->stableBits, WC_PUF_STABLE_BYTES,
                       ctx->identity, WC_PUF_ID_SZ,
                       info, infoSz,
                       key, keySz);
        if (ret != 0)
            return PUF_DERIVE_KEY_E;

        return 0;
    }
#else
    (void)info;
    (void)infoSz;
    return PUF_DERIVE_KEY_E;
#endif
}

int wc_PufGetIdentity(PufCtx* ctx, byte* id, word32 idSz)
{
    if (ctx == NULL || id == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_READY))
        return PUF_IDENTITY_E;
    if (idSz < WC_PUF_ID_SZ)
        return PUF_IDENTITY_E;

    XMEMCPY(id, ctx->identity, WC_PUF_ID_SZ);
    return 0;
}

int wc_PufZeroize(PufCtx* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ForceZero(ctx, sizeof(PufCtx));
    return 0;
}

#ifdef WOLFSSL_PUF_TEST
int wc_PufSetTestData(PufCtx* ctx, const byte* data, word32 sz)
{
    if (ctx == NULL || data == NULL)
        return BAD_FUNC_ARG;
    if (sz < WC_PUF_RAW_BYTES)
        return PUF_READ_E;

    ctx->testSram = data;
    ctx->testSramSz = sz;

    /* copy test data directly into rawSram */
    XMEMCPY(ctx->rawSram, data, WC_PUF_RAW_BYTES);
    return 0;
}
#endif /* WOLFSSL_PUF_TEST */

#endif /* !HAVE_FIPS */
#endif /* WOLFSSL_PUF */
