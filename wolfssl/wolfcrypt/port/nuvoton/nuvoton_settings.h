/* nuvoton_settings.h
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

/* Build settings for the Nuvoton NuMicro M2354 port. Macros only, no BSP
 * headers, so settings.h can include it early.
 *
 * WOLFSSL_NUVOTON_M2354 turns the port on and is always needed. On its own it
 * offloads every engine we support. Name one or more of these instead and only
 * those are offloaded:
 *       WOLFSSL_NUVOTON_TRNG    - the standalone TRNG (rng.h)
 *       WOLFSSL_NUVOTON_HASH    - CRPT SHA-1/224/256/384/512
 *       WOLFSSL_NUVOTON_CIPHER  - CRPT AES (ECB/CBC/CTR/GCM/CCM)
 *       WOLFSSL_NUVOTON_ECC     - CRPT ECC (also covers ECDH)
 *       WOLFSSL_NUVOTON_RSA     - CRPT RSA
 *       WOLFSSL_NUVOTON_KS      - Key Store wrapped keys
 *
 * Exactly one TrustZone model must be named:
 *       WOLFSSL_NUVOTON_SECURE  - wolfCrypt runs in the secure world and calls
 *                                 the BSP drivers directly. This is the right
 *                                 choice for a non-TrustZone application, which
 *                                 the M2354 also runs in the secure world.
 *       WOLFSSL_NUVOTON_NSC     - wolfCrypt runs in the non-secure world and
 *                                 reaches the hardware through cmse_nonsecure
 *                                 entry veneers. The port calls the same
 *                                 wc_nuvoton_hw_* interface either way; under
 *                                 this macro nuvoton_hw.c is not compiled and
 *                                 the veneers satisfy the symbols instead.
 *
 * Other switches:
 *       WOLFSSL_NUVOTON_DEVID        - crypto callback device ID (default 820)
 *       WOLFSSL_NUVOTON_DMA_BUF_SZ   - bounce buffer size, see below
 *       WOLFSSL_NUVOTON_HW_TIMEOUT   - engine poll limit, see below
 */

#ifndef WOLFSSL_NUVOTON_SETTINGS_H
#define WOLFSSL_NUVOTON_SETTINGS_H

#ifdef WOLFSSL_NUVOTON_M2354

/* The port works through the wolfSSL crypto callback. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* Streaming hashes are copied (wc_Sha256Copy) and freed, and AES and ECC keys
 * carry a Key Store handle that has to be released with the object. */
#ifndef WOLF_CRYPTO_CB_COPY
    #define WOLF_CRYPTO_CB_COPY
#endif
#ifndef WOLF_CRYPTO_CB_FREE
    #define WOLF_CRYPTO_CB_FREE
#endif

/* Which world wolfCrypt is built for. There is no software fallback for
 * guessing wrong - a non-secure build that calls the BSP directly faults on
 * the first CRPT access - so a conflict is an error, and silence defaults to
 * the secure world, which is where a non-TrustZone M2354 application runs. */
#if defined(WOLFSSL_NUVOTON_SECURE) && defined(WOLFSSL_NUVOTON_NSC)
    #error "Name only one of WOLFSSL_NUVOTON_SECURE or WOLFSSL_NUVOTON_NSC"
#endif
#if !defined(WOLFSSL_NUVOTON_SECURE) && !defined(WOLFSSL_NUVOTON_NSC)
    #define WOLFSSL_NUVOTON_SECURE
#endif

/* No engine was named, so turn them all on. */
#if !defined(WOLFSSL_NUVOTON_TRNG)   && \
    !defined(WOLFSSL_NUVOTON_HASH)   && \
    !defined(WOLFSSL_NUVOTON_CIPHER) && \
    !defined(WOLFSSL_NUVOTON_ECC)    && \
    !defined(WOLFSSL_NUVOTON_RSA)    && \
    !defined(WOLFSSL_NUVOTON_KS)
    #define WOLFSSL_NUVOTON_TRNG
    #define WOLFSSL_NUVOTON_HASH
    #define WOLFSSL_NUVOTON_CIPHER
    /* Leave RSA off in a build without RSA. */
    #ifndef NO_RSA
        #define WOLFSSL_NUVOTON_RSA
    #endif
    /* HAVE_ECC is decided later, so set this now and let nuvoton_cb_pk.c
     * check. */
    #define WOLFSSL_NUVOTON_ECC
    #define WOLFSSL_NUVOTON_KS
#endif

/* The Key Store is reachable only from the secure world: M2354.h aliases KS to
 * KS_S unconditionally, with no KS_NS counterpart, unlike CRPT. A non-secure
 * build therefore has to go through a veneer, which is what WOLFSSL_NUVOTON_NSC
 * arranges; this is only a note, not a restriction. */

/* A Key Store handle rides in the devCtx of the Aes or ecc_key it belongs to,
 * so the port needs no set-key hook and no new struct member. */

/* The CRPT ECC and RSA drivers take key material as NUL terminated hex
 * strings, so the port needs the converter asn.c already has for the custom
 * ECC curve parameter strings. Base16_Decode() covers the other direction and
 * is public already. */
#if (defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA)) && \
    !defined(WOLFSSL_ASN_HEX_STRING)
    #define WOLFSSL_ASN_HEX_STRING
#endif

/* Crypto callback device ID. Chosen clear of the IDs the other ports pick by
 * default (STM32 806-808, RealTek 810-811). */
#ifndef WOLFSSL_NUVOTON_DEVID
    #define WOLFSSL_NUVOTON_DEVID 820
#endif

/* Make the unmodified test and benchmark drive the port without being told a
 * device ID on the command line. */
#ifndef WC_USE_DEVID
    #define WC_USE_DEVID WOLFSSL_NUVOTON_DEVID
#endif

/* CRPT DMA reads and writes only word-aligned addresses in the 0x2xxxxxxx SRAM
 * region, so anything else is staged through a bounce buffer. The size is the
 * largest chunk handed to the engine in one go; it must be a multiple of the
 * AES block size. The BSP's own mbedTLS layer uses six blocks and that is the
 * default here too. Raising it trades static SRAM for fewer DMA rounds. */
#ifndef WOLFSSL_NUVOTON_DMA_BUF_SZ
    #define WOLFSSL_NUVOTON_DMA_BUF_SZ (16 * 6)
#endif
#if (WOLFSSL_NUVOTON_DMA_BUF_SZ % 16) != 0
    #error "WOLFSSL_NUVOTON_DMA_BUF_SZ must be a multiple of the AES block size"
#endif

/* Upper bound on the busy-wait for an engine to report done, in loop
 * iterations. The port polls rather than taking the CRPT interrupt so that it
 * needs no ISR from the application, the same choice the STM32 PKA port makes.
 * The bound only has to be generous: it exists so a wedged engine returns an
 * error instead of hanging the caller. */
#ifndef WOLFSSL_NUVOTON_HW_TIMEOUT
    #define WOLFSSL_NUVOTON_HW_TIMEOUT 5000000
#endif

/* Cortex-M23 is ARMv8-M baseline, that is Thumb-1. Pick the matching SP tier
 * unless the application has already chosen one. wolfSSL ships no Thumb-1
 * per-algorithm assembly, so WOLFSSL_ARMASM stays off; see
 * doc/ASM_AND_MATH_DEFINES.md. */
#if !defined(WOLFSSL_SP_ARM_THUMB) && !defined(WOLFSSL_SP_ARM_CORTEX_M) && \
    !defined(WOLFSSL_SP_ARM32) && !defined(WOLFSSL_SP_ARM64) && \
    !defined(WOLFSSL_SP_X86_64) && !defined(WOLFSSL_SP_MATH_ALL) && \
    !defined(WOLFSSL_NUVOTON_NO_SP_DEFAULT)
    #define WOLFSSL_SP_ARM_THUMB
#endif

/* No filesystem and no OS entropy device on this part. */
#ifndef NO_DEV_RANDOM
    #define NO_DEV_RANDOM
#endif

#endif /* WOLFSSL_NUVOTON_M2354 */

#endif /* WOLFSSL_NUVOTON_SETTINGS_H */
