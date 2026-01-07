/* ct_intrinsics_test.c
 *
 * Test suite for wolfSSL constant-time intrinsics compatibility layer
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file tests the ct_intrinsics.h header to verify that the constant-time
 * macros work correctly with both the LLVM 22 intrinsics (when available) and
 * the fallback implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* wolfSSL configuration */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ct_intrinsics.h>

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("  [FAIL] %s\n", msg); \
    } \
} while(0)

/* ============================================================================
 * Test WC_CT_SELECT8
 * ============================================================================ */
void test_ct_select8(void) {
    byte result;

    printf("\nTesting WC_CT_SELECT8:\n");

    /* Test with condition true */
    result = WC_CT_SELECT8(1, 0xAA, 0x55);
    TEST_ASSERT(result == 0xAA, "SELECT8: condition true returns val_true");

    /* Test with condition false */
    result = WC_CT_SELECT8(0, 0xAA, 0x55);
    TEST_ASSERT(result == 0x55, "SELECT8: condition false returns val_false");

    /* Test with various true values */
    result = WC_CT_SELECT8(100, 0xFF, 0x00);
    TEST_ASSERT(result == 0xFF, "SELECT8: non-zero condition returns val_true");

    result = WC_CT_SELECT8(-1, 0xFF, 0x00);
    TEST_ASSERT(result == 0xFF, "SELECT8: negative condition returns val_true");

    /* Edge cases */
    result = WC_CT_SELECT8(1, 0x00, 0xFF);
    TEST_ASSERT(result == 0x00, "SELECT8: can select zero");

    result = WC_CT_SELECT8(0, 0x00, 0xFF);
    TEST_ASSERT(result == 0xFF, "SELECT8: can select 0xFF");
}

/* ============================================================================
 * Test WC_CT_SELECT16
 * ============================================================================ */
void test_ct_select16(void) {
    word16 result;

    printf("\nTesting WC_CT_SELECT16:\n");

    result = WC_CT_SELECT16(1, 0xAAAA, 0x5555);
    TEST_ASSERT(result == 0xAAAA, "SELECT16: condition true returns val_true");

    result = WC_CT_SELECT16(0, 0xAAAA, 0x5555);
    TEST_ASSERT(result == 0x5555, "SELECT16: condition false returns val_false");

    result = WC_CT_SELECT16(1, 0xFFFF, 0x0000);
    TEST_ASSERT(result == 0xFFFF, "SELECT16: can select 0xFFFF");

    result = WC_CT_SELECT16(0, 0xFFFF, 0x0000);
    TEST_ASSERT(result == 0x0000, "SELECT16: can select 0x0000");
}

/* ============================================================================
 * Test WC_CT_SELECT32
 * ============================================================================ */
void test_ct_select32(void) {
    word32 result;

    printf("\nTesting WC_CT_SELECT32:\n");

    result = WC_CT_SELECT32(1, 0xAAAAAAAA, 0x55555555);
    TEST_ASSERT(result == 0xAAAAAAAA, "SELECT32: condition true returns val_true");

    result = WC_CT_SELECT32(0, 0xAAAAAAAA, 0x55555555);
    TEST_ASSERT(result == 0x55555555, "SELECT32: condition false returns val_false");

    /* Test with large values */
    result = WC_CT_SELECT32(1, 0xFFFFFFFF, 0x00000000);
    TEST_ASSERT(result == 0xFFFFFFFF, "SELECT32: can select max value");

    result = WC_CT_SELECT32(0, 0xFFFFFFFF, 0x00000000);
    TEST_ASSERT(result == 0x00000000, "SELECT32: can select zero");

    /* Test with actual comparison condition */
    int a = 10, b = 5;
    result = WC_CT_SELECT32(a > b, 100, 200);
    TEST_ASSERT(result == 100, "SELECT32: works with comparison condition (true)");

    result = WC_CT_SELECT32(a < b, 100, 200);
    TEST_ASSERT(result == 200, "SELECT32: works with comparison condition (false)");
}

/* ============================================================================
 * Test WC_CT_SELECT64 (if available)
 * ============================================================================ */
#ifdef WORD64_AVAILABLE
void test_ct_select64(void) {
    word64 result;

    printf("\nTesting WC_CT_SELECT64:\n");

    result = WC_CT_SELECT64(1, 0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL);
    TEST_ASSERT(result == 0xAAAAAAAAAAAAAAAAULL, "SELECT64: condition true returns val_true");

    result = WC_CT_SELECT64(0, 0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL);
    TEST_ASSERT(result == 0x5555555555555555ULL, "SELECT64: condition false returns val_false");

    result = WC_CT_SELECT64(1, 0xFFFFFFFFFFFFFFFFULL, 0x0000000000000000ULL);
    TEST_ASSERT(result == 0xFFFFFFFFFFFFFFFFULL, "SELECT64: can select max value");
}
#endif

/* ============================================================================
 * Test WC_CT_EQ and WC_CT_NE
 * ============================================================================ */
void test_ct_eq_ne(void) {
    word32 result;

    printf("\nTesting WC_CT_EQ and WC_CT_NE:\n");

    /* Test equality */
    result = WC_CT_EQ(5, 5);
    TEST_ASSERT(result != 0, "CT_EQ: equal values return non-zero");

    result = WC_CT_EQ(5, 6);
    TEST_ASSERT(result == 0, "CT_EQ: unequal values return zero");

    result = WC_CT_EQ(0, 0);
    TEST_ASSERT(result != 0, "CT_EQ: zero equals zero");

    /* Test inequality */
    result = WC_CT_NE(5, 6);
    TEST_ASSERT(result != 0, "CT_NE: unequal values return non-zero");

    result = WC_CT_NE(5, 5);
    TEST_ASSERT(result == 0, "CT_NE: equal values return zero");
}

/* ============================================================================
 * Test WC_CT_IS_ZERO and WC_CT_IS_NONZERO
 * ============================================================================ */
void test_ct_is_zero(void) {
    word32 result;

    printf("\nTesting WC_CT_IS_ZERO and WC_CT_IS_NONZERO:\n");

    result = WC_CT_IS_ZERO(0);
    TEST_ASSERT(result != 0, "CT_IS_ZERO: zero returns non-zero");

    result = WC_CT_IS_ZERO(1);
    TEST_ASSERT(result == 0, "CT_IS_ZERO: non-zero returns zero");

    result = WC_CT_IS_ZERO(0xFFFFFFFF);
    TEST_ASSERT(result == 0, "CT_IS_ZERO: max value returns zero");

    result = WC_CT_IS_NONZERO(1);
    TEST_ASSERT(result != 0, "CT_IS_NONZERO: non-zero returns non-zero");

    result = WC_CT_IS_NONZERO(0);
    TEST_ASSERT(result == 0, "CT_IS_NONZERO: zero returns zero");
}

/* ============================================================================
 * Test WC_CT_MIN and WC_CT_MAX
 * ============================================================================ */
void test_ct_min_max(void) {
    word32 result;

    printf("\nTesting WC_CT_MIN and WC_CT_MAX:\n");

    result = WC_CT_MIN(5, 10);
    TEST_ASSERT(result == 5, "CT_MIN: returns smaller value (5 < 10)");

    result = WC_CT_MIN(10, 5);
    TEST_ASSERT(result == 5, "CT_MIN: returns smaller value (10 > 5)");

    result = WC_CT_MIN(5, 5);
    TEST_ASSERT(result == 5, "CT_MIN: equal values return that value");

    result = WC_CT_MAX(5, 10);
    TEST_ASSERT(result == 10, "CT_MAX: returns larger value (5 < 10)");

    result = WC_CT_MAX(10, 5);
    TEST_ASSERT(result == 10, "CT_MAX: returns larger value (10 > 5)");

    result = WC_CT_MAX(5, 5);
    TEST_ASSERT(result == 5, "CT_MAX: equal values return that value");
}

/* ============================================================================
 * Test for consistent behavior
 * ============================================================================ */
void test_consistency(void) {
    printf("\nTesting consistency across multiple values:\n");

    int i;
    int consistent = 1;

    /* Test that SELECT32 is consistent across all condition values */
    for (i = 1; i <= 100 && consistent; i++) {
        word32 r = WC_CT_SELECT32(i, 0xAAAAAAAA, 0x55555555);
        if (r != 0xAAAAAAAA) {
            consistent = 0;
        }
    }
    TEST_ASSERT(consistent, "SELECT32: consistent for all positive conditions");

    consistent = 1;
    for (i = -100; i < 0 && consistent; i++) {
        word32 r = WC_CT_SELECT32(i, 0xAAAAAAAA, 0x55555555);
        if (r != 0xAAAAAAAA) {
            consistent = 0;
        }
    }
    TEST_ASSERT(consistent, "SELECT32: consistent for all negative conditions");
}

/* ============================================================================
 * Main
 * ============================================================================ */
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("===============================================\n");
    printf("  wolfSSL CT Intrinsics Test Suite\n");
    printf("===============================================\n");

#ifdef WC_CT_INTRINSICS_AVAILABLE
    printf("\nUsing LLVM 22+ native __builtin_ct_select intrinsics\n");
#else
    printf("\nUsing fallback mask-based implementation\n");
#endif

    printf("\n");

    /* Run all tests */
    test_ct_select8();
    test_ct_select16();
    test_ct_select32();
#ifdef WORD64_AVAILABLE
    test_ct_select64();
#endif
    test_ct_eq_ne();
    test_ct_is_zero();
    test_ct_min_max();
    test_consistency();

    /* Print summary */
    printf("\n===============================================\n");
    printf("  Summary\n");
    printf("===============================================\n");
    printf("  Tests run:    %d\n", tests_run);
    printf("  Passed:       %d\n", tests_passed);
    printf("  Failed:       %d\n", tests_failed);
    printf("===============================================\n");

    return tests_failed > 0 ? 1 : 0;
}
