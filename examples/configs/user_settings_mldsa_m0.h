/* user_settings_mldsa_m0.h
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

/* ML-DSA (FIPS 204) on a small Cortex-M, no TLS and no hardware crypto.
 *
 * Defaults to verify only at the smallest RAM, which is the usual secure-boot
 * and firmware-update case. The #if blocks below switch to the faster verify,
 * to an allocator-free verify, or to a build that also generates keys and
 * signs. Choose the parameter set under "Parameter sets": code size is nearly
 * the same for each, so the choice is driven by RAM and signature size.
 *
 * Measured on a NUCLEO-G071RB (Cortex-M0+, 64 MHz, 128 KB flash / 36 KB RAM),
 * portable C, no ARMv6-M assembly for Keccak or the NTT. ML-DSA-87 verify in
 * the default profile is about 374 ms using a 3.0 KB key object and 5.3 KB of
 * heap; ML-DSA-44 is about 126 ms using 1.7 KB and 4.9 KB. The faster profile
 * below cuts those times by a third at ML-DSA-44 and by about half at
 * ML-DSA-87, for 3 to 6 KB more RAM. Signing needs the smallest-memory signer
 * to fit ML-DSA-87 on 36 KB. Budget about 3.4 KB of stack. See
 * doc/ALGORITHM_DEFINES.md for what each memory option does.
 *
 * Derived from:
 * ./configure \
 *   --enable-cryptonly --enable-experimental \
 *   --enable-dilithium=yes,small,verify-only \
 *   --enable-sha3 --disable-rsa --disable-ecc --disable-dh \
 *   CFLAGS="-DWOLFSSL_MLDSA_VERIFY_SMALLEST_MEM -DWOLFSSL_MLDSA_NO_ASN1 \
 *       -DWOLFSSL_MLDSA_NO_LARGE_CODE -DWOLFSSL_MLDSA_ALIGNMENT=4"
 *
 * Build and test:
 * cp ./examples/configs/user_settings_mldsa_m0.h user_settings.h
 * ./configure --enable-usersettings --disable-examples
 * make
 * ./wolfcrypt/test/testwolfcrypt
 */


#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* Platform */
/* ------------------------------------------------- */
#define WOLFCRYPT_ONLY /* No TLS, wolfCrypt only */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_EXPERIMENTAL_SETTINGS

/* Endianness - defaults to little endian */
#ifdef __BIG_ENDIAN__
    #define BIG_ENDIAN_ORDER
#endif

/* ARMv6-M (Cortex-M0/M0+) cannot do unaligned word access. Harmless on
 * cores that can. */
#define WOLFSSL_MLDSA_ALIGNMENT 4

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
/* ML-DSA needs no big-number math. Left here for a build that adds ECC. */
#if 0
    #define WOLFSSL_SP
    #define WOLFSSL_SP_SMALL
    #define WOLFSSL_SP_MATH
#endif

/* ------------------------------------------------- */
/* ML-DSA */
/* ------------------------------------------------- */
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_MLDSA_SMALL        /* Small-code variants of the kernels */
#define WOLFSSL_MLDSA_NO_LARGE_CODE
#define WOLFSSL_MLDSA_NO_ASN1      /* Raw keys, no ASN.1 or OID tables */

/* Verify: stream vector z a polynomial at a time. Smallest RAM. */
#define WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM

#if 0 /* Faster verify: keep the decoded vector instead of re-deriving it.
       * A third quicker at ML-DSA-44, about half at ML-DSA-87, for 3 to 6 KB
       * more heap. */
    #undef  WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM
    #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
#endif

#if 0 /* No allocator at all: pin the verify buffers in the key for its whole
       * lifetime. Adds about 5 KB to sizeof(wc_MlDsaKey) and removes every
       * allocation. Total RAM is within a few hundred bytes of the default,
       * so enable this for a heapless build, not to save memory. */
    #define WOLFSSL_MLDSA_VERIFY_NO_MALLOC
#endif

#if 1 /* Verify only. Clear this to also generate keys and sign. */
    #define WOLFSSL_MLDSA_VERIFY_ONLY
#else
    #define WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM
    /* Hold one polynomial of the mask instead of the whole vector and
     * regenerate it. Slightly slower than WOLFSSL_MLDSA_SIGN_SMALL_MEM but
     * roughly a third less heap, and it is what fits ML-DSA-87 signing on a
     * 36 KB part. */
    #define WOLFSSL_MLDSA_SIGN_SMALLEST_MEM
    #define WOLFSSL_MLDSA_DYNAMIC_KEYS
#endif

/* ------------------------------------------------- */
/* Parameter sets */
/* ------------------------------------------------- */
/* All three are built by default and cost about 0.6 KB of code together over
 * any one of them. Drop the ones you do not need: a device that only verifies
 * its own vendor's signatures needs exactly one. */
#if 0
    #define WOLFSSL_NO_ML_DSA_44
#endif
#if 0
    #define WOLFSSL_NO_ML_DSA_65
#endif
#if 0
    #define WOLFSSL_NO_ML_DSA_87
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* ML-DSA is mostly Keccak, so these are not optional. */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
/* Key generation and signing need entropy; verification does not. Implement
 * wc_GenerateSeed() for the target, or define CUSTOM_RAND_GENERATE_SEED. */
#if 0 /* Verify-only build with no RNG at all */
    #define WC_NO_RNG
    #define WC_NO_HASHDRBG
#endif

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_AES
#define NO_AES_CBC
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS8
#define NO_SIG_WRAPPER
#if 1 /* No ECC. Clear for a hybrid ECDSA + ML-DSA build. */
    #define NO_ECC
#endif

/* ------------------------------------------------- */
/* Disabled Features */
/* ------------------------------------------------- */
#define NO_ASN
#define NO_CERTS
#define NO_CODING
#define WOLFSSL_NO_PEM
#define NO_PSK
#define NO_WOLFSSL_MEMORY

/* ------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------- */
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#endif
#if 1 /* Disable error strings to save flash */
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
