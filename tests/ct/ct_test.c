/*
 * ct_test.c - Constant-Time Testing for wolfSSL using dudect
 *
 * This file tests wolfSSL's constant-time implementations for timing leaks
 * using the dudect statistical testing methodology.
 *
 * Based on: https://github.com/oreparaz/dudect
 * Paper: "dude, is my code constant time?" (DATE 2017)
 *
 * Reference: Trail of Bits LLVM CT support:
 * https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/
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
#include <wolfssl/wolfcrypt/random.h>

/* Include misc.c inline functions */
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>

/* Test configuration */
#define DUDECT_IMPLEMENTATION
#define DUDECT_VISIBLITY_STATIC
#include "dudect.h"

/* Number of measurements per test */
#define NUMBER_MEASUREMENTS 1000000

/* Test data size */
#define TEST_DATA_SIZE 32

/*
 * Test classes:
 * - Class 0: Fixed input (e.g., all zeros)
 * - Class 1: Random input
 *
 * If the function is constant-time, both classes should have
 * statistically indistinguishable timing distributions.
 */

/* ============================================================================
 * Test 1: ConstantCompare
 * ============================================================================
 * Tests if byte array comparison runs in constant time regardless of
 * where the first difference occurs.
 */

static uint8_t ct_compare_data_a[TEST_DATA_SIZE];
static uint8_t ct_compare_data_b[TEST_DATA_SIZE];

uint8_t do_one_computation_constant_compare(uint8_t *data) {
    /* Copy test data */
    memcpy(ct_compare_data_a, data, TEST_DATA_SIZE);

    /* Class determines whether arrays match or differ early vs late */
    int result = ConstantCompare(ct_compare_data_a, ct_compare_data_b, TEST_DATA_SIZE);

    return (uint8_t)(result & 0xFF);
}

void prepare_inputs_constant_compare(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    (void)c;

    /* Initialize fixed comparison target */
    memset(ct_compare_data_b, 0x00, TEST_DATA_SIZE);

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = rand() % 2;

        if (classes[i] == 0) {
            /* Class 0: Arrays match (all zeros) */
            memset(&input_data[i * c->chunk_size], 0x00, c->chunk_size);
        } else {
            /* Class 1: Arrays differ at random position */
            memset(&input_data[i * c->chunk_size], 0x00, c->chunk_size);
            /* Set a random byte to non-zero at random position */
            size_t pos = rand() % TEST_DATA_SIZE;
            input_data[i * c->chunk_size + pos] = (uint8_t)(rand() % 255 + 1);
        }
    }
}

/* ============================================================================
 * Test 2: ctMaskSel (byte selection)
 * ============================================================================
 * Tests if conditional byte selection runs in constant time.
 */

uint8_t do_one_computation_ctMaskSel(uint8_t *data) {
    uint8_t condition = data[0];
    uint8_t val_a = data[1];
    uint8_t val_b = data[2];

    /* Create mask from condition */
    byte mask = ctMaskGT((int)condition, 127);

    /* Select value based on mask */
    return ctMaskSel(mask, val_a, val_b);
}

void prepare_inputs_ctMaskSel(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    (void)c;

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = rand() % 2;

        uint8_t *data = &input_data[i * c->chunk_size];

        if (classes[i] == 0) {
            /* Class 0: condition < 128 (mask will be 0x00) */
            data[0] = (uint8_t)(rand() % 128);
        } else {
            /* Class 1: condition >= 128 (mask will be 0xFF) */
            data[0] = (uint8_t)(128 + (rand() % 128));
        }

        /* Random values for a and b */
        data[1] = (uint8_t)rand();
        data[2] = (uint8_t)rand();
    }
}

/* ============================================================================
 * Test 3: ctMaskGT (greater-than comparison)
 * ============================================================================
 * Tests if greater-than mask generation runs in constant time.
 */

uint8_t do_one_computation_ctMaskGT(uint8_t *data) {
    int a = (int)data[0];
    int b = (int)data[1];

    return ctMaskGT(a, b);
}

void prepare_inputs_ctMaskGT(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    (void)c;

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = rand() % 2;

        uint8_t *data = &input_data[i * c->chunk_size];

        if (classes[i] == 0) {
            /* Class 0: a <= b */
            data[0] = (uint8_t)(rand() % 128);
            data[1] = (uint8_t)(128 + (rand() % 128));
        } else {
            /* Class 1: a > b */
            data[0] = (uint8_t)(128 + (rand() % 128));
            data[1] = (uint8_t)(rand() % 128);
        }
    }
}

/* ============================================================================
 * Test 4: ctMaskEq (equality comparison)
 * ============================================================================
 * Tests if equality mask generation runs in constant time.
 */

uint8_t do_one_computation_ctMaskEq(uint8_t *data) {
    int a = (int)data[0];
    int b = (int)data[1];

    return ctMaskEq(a, b);
}

void prepare_inputs_ctMaskEq(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    (void)c;

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = rand() % 2;

        uint8_t *data = &input_data[i * c->chunk_size];

        if (classes[i] == 0) {
            /* Class 0: a == b */
            data[0] = (uint8_t)(rand() % 256);
            data[1] = data[0];
        } else {
            /* Class 1: a != b */
            data[0] = (uint8_t)(rand() % 256);
            data[1] = (uint8_t)((data[0] + 1 + (rand() % 254)) % 256);
        }
    }
}

/* ============================================================================
 * Test 5: ctMaskCopy (conditional copy)
 * ============================================================================
 * Tests if conditional memory copy runs in constant time.
 */

static uint8_t ct_copy_dst[TEST_DATA_SIZE];
static uint8_t ct_copy_src[TEST_DATA_SIZE];

uint8_t do_one_computation_ctMaskCopy(uint8_t *data) {
    byte mask = data[0];

    /* Initialize source with test pattern */
    memcpy(ct_copy_src, &data[1], TEST_DATA_SIZE - 1);
    ct_copy_src[TEST_DATA_SIZE - 1] = 0;

    /* Initialize destination */
    memset(ct_copy_dst, 0xAA, TEST_DATA_SIZE);

    /* Perform conditional copy */
    ctMaskCopy(mask, ct_copy_dst, ct_copy_src, TEST_DATA_SIZE);

    /* Return checksum of destination */
    uint8_t sum = 0;
    for (int i = 0; i < TEST_DATA_SIZE; i++) {
        sum ^= ct_copy_dst[i];
    }
    return sum;
}

void prepare_inputs_ctMaskCopy(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    (void)c;

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = rand() % 2;

        uint8_t *data = &input_data[i * c->chunk_size];

        if (classes[i] == 0) {
            /* Class 0: mask is 0x00 (no copy) */
            data[0] = 0x00;
        } else {
            /* Class 1: mask is 0xFF (copy) */
            data[0] = 0xFF;
        }

        /* Random source data */
        for (size_t j = 1; j < c->chunk_size && j < TEST_DATA_SIZE; j++) {
            data[j] = (uint8_t)rand();
        }
    }
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

typedef struct {
    const char *name;
    uint8_t (*do_one_computation)(uint8_t *);
    void (*prepare_inputs)(dudect_config_t *, uint8_t *, uint8_t *);
    size_t chunk_size;
} ct_test_t;

static ct_test_t tests[] = {
    {
        .name = "ConstantCompare",
        .do_one_computation = do_one_computation_constant_compare,
        .prepare_inputs = prepare_inputs_constant_compare,
        .chunk_size = TEST_DATA_SIZE
    },
    {
        .name = "ctMaskSel",
        .do_one_computation = do_one_computation_ctMaskSel,
        .prepare_inputs = prepare_inputs_ctMaskSel,
        .chunk_size = 4
    },
    {
        .name = "ctMaskGT",
        .do_one_computation = do_one_computation_ctMaskGT,
        .prepare_inputs = prepare_inputs_ctMaskGT,
        .chunk_size = 4
    },
    {
        .name = "ctMaskEq",
        .do_one_computation = do_one_computation_ctMaskEq,
        .prepare_inputs = prepare_inputs_ctMaskEq,
        .chunk_size = 4
    },
    {
        .name = "ctMaskCopy",
        .do_one_computation = do_one_computation_ctMaskCopy,
        .prepare_inputs = prepare_inputs_ctMaskCopy,
        .chunk_size = TEST_DATA_SIZE
    },
};

#define NUM_TESTS (sizeof(tests) / sizeof(tests[0]))

/* Global state for current test */
static ct_test_t *current_test = NULL;

uint8_t do_one_computation(uint8_t *data) {
    return current_test->do_one_computation(data);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    current_test->prepare_inputs(c, input_data, classes);
}

int run_single_test(ct_test_t *test, int quick_mode) {
    printf("\n");
    printf("========================================\n");
    printf("Testing: %s\n", test->name);
    printf("========================================\n");

    current_test = test;

    dudect_config_t config = {
        .chunk_size = test->chunk_size,
        .number_measurements = quick_mode ? 10000 : NUMBER_MEASUREMENTS,
    };

    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);

    /* Run the test */
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;

    /* Limit iterations for reasonable runtime */
    int max_iterations = quick_mode ? 10 : 100;

    for (int i = 0; i < max_iterations && state == DUDECT_NO_LEAKAGE_EVIDENCE_YET; i++) {
        state = dudect_main(&ctx);

        if (i % 5 == 0) {
            printf("  Iteration %d: ", i);
            switch (state) {
                case DUDECT_NO_LEAKAGE_EVIDENCE_YET:
                    printf("no leakage detected yet\n");
                    break;
                case DUDECT_LEAKAGE_FOUND:
                    printf("LEAKAGE DETECTED!\n");
                    break;
            }
        }
    }

    printf("\n");
    printf("Result for %s: ", test->name);

    int passed = 0;
    switch (state) {
        case DUDECT_NO_LEAKAGE_EVIDENCE_YET:
            printf("PASS - No timing leakage detected\n");
            passed = 1;
            break;
        case DUDECT_LEAKAGE_FOUND:
            printf("FAIL - Timing leakage detected!\n");
            passed = 0;
            break;
    }

    dudect_free(&ctx);

    return passed;
}

void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("wolfSSL Constant-Time Test Suite using dudect\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -q, --quick    Quick mode (fewer measurements)\n");
    printf("  -t, --test N   Run only test number N (0-%zu)\n", NUM_TESTS - 1);
    printf("  -l, --list     List available tests\n");
    printf("\n");
    printf("Available tests:\n");
    for (size_t i = 0; i < NUM_TESTS; i++) {
        printf("  %zu: %s\n", i, tests[i].name);
    }
}

int main(int argc, char *argv[]) {
    int quick_mode = 0;
    int single_test = -1;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quick") == 0) {
            quick_mode = 1;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            printf("Available tests:\n");
            for (size_t j = 0; j < NUM_TESTS; j++) {
                printf("  %zu: %s\n", j, tests[j].name);
            }
            return 0;
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) && i + 1 < argc) {
            single_test = atoi(argv[++i]);
            if (single_test < 0 || (size_t)single_test >= NUM_TESTS) {
                fprintf(stderr, "Invalid test number: %d\n", single_test);
                return 1;
            }
        }
    }

    printf("===============================================\n");
    printf("  wolfSSL Constant-Time Test Suite (dudect)\n");
    printf("===============================================\n");
    printf("\n");
    printf("Mode: %s\n", quick_mode ? "Quick" : "Full");
    printf("Measurements per iteration: %d\n", quick_mode ? 100000 : NUMBER_MEASUREMENTS);
    printf("\n");
    printf("This test uses statistical analysis to detect timing leaks.\n");
    printf("A t-value > 4.5 indicates potential timing leakage.\n");

    /* Seed random number generator */
    srand(42);  /* Fixed seed for reproducibility */

    int passed = 0;
    int failed = 0;

    if (single_test >= 0) {
        /* Run single test */
        if (run_single_test(&tests[single_test], quick_mode)) {
            passed++;
        } else {
            failed++;
        }
    } else {
        /* Run all tests */
        for (size_t i = 0; i < NUM_TESTS; i++) {
            if (run_single_test(&tests[i], quick_mode)) {
                passed++;
            } else {
                failed++;
            }
        }
    }

    printf("\n");
    printf("===============================================\n");
    printf("  Summary\n");
    printf("===============================================\n");
    printf("  Passed: %d\n", passed);
    printf("  Failed: %d\n", failed);
    printf("===============================================\n");

    return failed > 0 ? 1 : 0;
}
