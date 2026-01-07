/* ct_intrinsics.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * \file wolfssl/wolfcrypt/ct_intrinsics.h
 * \brief Constant-time intrinsics compatibility layer
 *
 * This header provides a compatibility layer for LLVM 22's constant-time
 * intrinsics (__builtin_ct_select). When available, these intrinsics provide
 * compiler-level guarantees that constant-time operations won't be optimized
 * into timing-vulnerable code.
 *
 * Reference:
 * https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/
 *
 * Usage:
 *   result = WC_CT_SELECT(condition, value_if_true, value_if_false);
 *   result = WC_CT_SELECT8(condition, val_true, val_false);
 *   result = WC_CT_SELECT32(condition, val_true, val_false);
 *   result = WC_CT_SELECT64(condition, val_true, val_false);
 */

#ifndef WOLF_CRYPT_CT_INTRINSICS_H
#define WOLF_CRYPT_CT_INTRINSICS_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*
 * Detection of LLVM 22+ with __builtin_ct_select support
 *
 * The __builtin_ct_select family of intrinsics was introduced in LLVM 22
 * to provide compiler-guaranteed constant-time conditional selection.
 *
 * When these intrinsics are available, they guarantee:
 * 1. The selection compiles to constant-time machine code (e.g., cmov on x86)
 * 2. The optimizer won't transform the operation into branching code
 * 3. The constant-time property is preserved through all optimization passes
 */

/* Check for LLVM/Clang with __builtin_ct_select support */
#if defined(__clang__)
    /* Check for Clang version 22 or later */
    #if __clang_major__ >= 22
        #define WC_CT_INTRINSICS_AVAILABLE 1
    #endif
#endif

/* Allow user to force enable/disable */
#ifdef WOLFSSL_FORCE_CT_INTRINSICS
    #undef WC_CT_INTRINSICS_AVAILABLE
    #define WC_CT_INTRINSICS_AVAILABLE 1
#endif

#ifdef WOLFSSL_NO_CT_INTRINSICS
    #undef WC_CT_INTRINSICS_AVAILABLE
#endif


#ifdef WC_CT_INTRINSICS_AVAILABLE
/*
 * LLVM 22+ native intrinsics available
 *
 * These intrinsics provide compiler-level guarantees for constant-time
 * execution. The compiler will emit appropriate constant-time instructions
 * (e.g., cmov on x86-64, csel on ARM64) and prevent any optimization that
 * would break the constant-time property.
 */

/* Generic constant-time select */
#define WC_CT_SELECT(cond, val_true, val_false) \
    __builtin_ct_select((cond), (val_true), (val_false))

/* Type-specific constant-time select (may have optimized implementations) */
#define WC_CT_SELECT8(cond, val_true, val_false) \
    ((byte)__builtin_ct_select((cond), (val_true), (val_false)))

#define WC_CT_SELECT16(cond, val_true, val_false) \
    ((word16)__builtin_ct_select((cond), (val_true), (val_false)))

#define WC_CT_SELECT32(cond, val_true, val_false) \
    ((word32)__builtin_ct_select((cond), (val_true), (val_false)))

#ifdef WORD64_AVAILABLE
#define WC_CT_SELECT64(cond, val_true, val_false) \
    ((word64)__builtin_ct_select((cond), (val_true), (val_false)))
#endif

/* Constant-time comparison - returns non-zero if a == b */
#define WC_CT_EQ(a, b) \
    __builtin_ct_select((a) == (b), 1, 0)

/* Constant-time comparison - returns non-zero if a != b */
#define WC_CT_NE(a, b) \
    __builtin_ct_select((a) != (b), 1, 0)

#else /* !WC_CT_INTRINSICS_AVAILABLE */
/*
 * Fallback implementation using traditional mask-based constant-time code
 *
 * These implementations use bitwise operations to achieve constant-time
 * behavior. While compilers typically preserve these patterns, they don't
 * provide the same level of guarantee as the LLVM intrinsics.
 *
 * The pattern used is:
 *   result = (val_false & ~mask) | (val_true & mask)
 *
 * Where mask is all 1s if condition is true, all 0s otherwise.
 */

/* Helper: Convert boolean condition to all-bits mask
 * condition != 0 -> 0xFFFFFFFF (or appropriate width)
 * condition == 0 -> 0x00000000
 */
#define WC_CT_BOOL_TO_MASK32(cond) \
    ((word32)(0u - ((word32)((cond) != 0))))

#define WC_CT_BOOL_TO_MASK8(cond) \
    ((byte)(0u - ((byte)((cond) != 0))))

#ifdef WORD64_AVAILABLE
#define WC_CT_BOOL_TO_MASK64(cond) \
    ((word64)(0ull - ((word64)((cond) != 0))))
#endif

/* 8-bit constant-time select */
#define WC_CT_SELECT8(cond, val_true, val_false) \
    ((byte)(((byte)(val_false) & (byte)~WC_CT_BOOL_TO_MASK8(cond)) | \
            ((byte)(val_true) & WC_CT_BOOL_TO_MASK8(cond))))

/* 16-bit constant-time select */
#define WC_CT_SELECT16(cond, val_true, val_false) \
    ((word16)(((word16)(val_false) & (word16)~WC_CT_BOOL_TO_MASK32(cond)) | \
              ((word16)(val_true) & (word16)WC_CT_BOOL_TO_MASK32(cond))))

/* 32-bit constant-time select */
#define WC_CT_SELECT32(cond, val_true, val_false) \
    ((word32)(((word32)(val_false) & ~WC_CT_BOOL_TO_MASK32(cond)) | \
              ((word32)(val_true) & WC_CT_BOOL_TO_MASK32(cond))))

#ifdef WORD64_AVAILABLE
/* 64-bit constant-time select */
#define WC_CT_SELECT64(cond, val_true, val_false) \
    ((word64)(((word64)(val_false) & ~WC_CT_BOOL_TO_MASK64(cond)) | \
              ((word64)(val_true) & WC_CT_BOOL_TO_MASK64(cond))))
#endif

/* Generic select - defaults to 32-bit */
#define WC_CT_SELECT(cond, val_true, val_false) \
    WC_CT_SELECT32(cond, val_true, val_false)

/* Constant-time equality check */
#define WC_CT_EQ(a, b) \
    WC_CT_SELECT32((a) == (b), 1, 0)

/* Constant-time inequality check */
#define WC_CT_NE(a, b) \
    WC_CT_SELECT32((a) != (b), 1, 0)

#endif /* WC_CT_INTRINSICS_AVAILABLE */


/*
 * Portable constant-time operations that work across all configurations
 */

/* Constant-time zero check: returns 0 if val is 0, non-zero otherwise */
#define WC_CT_IS_ZERO(val) \
    WC_CT_SELECT32((val) == 0, 1, 0)

/* Constant-time non-zero check: returns non-zero if val is non-zero */
#define WC_CT_IS_NONZERO(val) \
    WC_CT_SELECT32((val) != 0, 1, 0)

/* Constant-time minimum */
#define WC_CT_MIN(a, b) \
    WC_CT_SELECT32((a) < (b), (a), (b))

/* Constant-time maximum */
#define WC_CT_MAX(a, b) \
    WC_CT_SELECT32((a) > (b), (a), (b))


/*
 * Feature detection macros for conditional compilation
 */

/* Check if we have native LLVM CT intrinsics */
#ifdef WC_CT_INTRINSICS_AVAILABLE
    #define HAVE_WC_CT_INTRINSICS
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_CT_INTRINSICS_H */
