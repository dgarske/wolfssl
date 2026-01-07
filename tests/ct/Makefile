# Makefile for wolfSSL Constant-Time Tests
#
# Uses dudect for statistical timing analysis

WOLFSSL_ROOT ?= ../..

CC ?= clang
CFLAGS = -O2 -Wall -Wextra
CFLAGS += -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/wolfssl
CFLAGS += -DHAVE_CONFIG_H
CFLAGS += -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT

# Link against wolfSSL if needed
LDFLAGS = -L$(WOLFSSL_ROOT)/src/.libs -lwolfssl -lm
LDFLAGS += -Wl,-rpath,$(WOLFSSL_ROOT)/src/.libs

# For static linking (if libwolfssl.a exists)
STATIC_LDFLAGS = $(WOLFSSL_ROOT)/src/.libs/libwolfssl.a -lm -lpthread

TARGETS = ct_test ct_intrinsics_test

.PHONY: all clean test quick-test test-intrinsics help

all: $(TARGETS)

ct_test: ct_test.c dudect.h
	@echo "Building CT test suite..."
	@if [ -f $(WOLFSSL_ROOT)/src/.libs/libwolfssl.a ]; then \
		echo "  Using static linking..."; \
		$(CC) $(CFLAGS) -o $@ ct_test.c $(STATIC_LDFLAGS); \
	elif [ -f $(WOLFSSL_ROOT)/src/.libs/libwolfssl.so ]; then \
		echo "  Using dynamic linking..."; \
		$(CC) $(CFLAGS) -o $@ ct_test.c $(LDFLAGS); \
	else \
		echo "  Building standalone (no libwolfssl)..."; \
		$(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS -o $@ ct_test.c -lm; \
	fi
	@echo "Build complete: $@"

ct_intrinsics_test: ct_intrinsics_test.c
	@echo "Building CT intrinsics test..."
	@if [ -f $(WOLFSSL_ROOT)/src/.libs/libwolfssl.a ]; then \
		$(CC) $(CFLAGS) -o $@ ct_intrinsics_test.c $(STATIC_LDFLAGS); \
	elif [ -f $(WOLFSSL_ROOT)/src/.libs/libwolfssl.so ]; then \
		$(CC) $(CFLAGS) -o $@ ct_intrinsics_test.c $(LDFLAGS); \
	else \
		$(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS -o $@ ct_intrinsics_test.c; \
	fi
	@echo "Build complete: $@"

test: ct_test
	@echo "Running full CT test suite..."
	./ct_test

quick-test: ct_test
	@echo "Running quick CT test suite..."
	./ct_test --quick

test-intrinsics: ct_intrinsics_test
	@echo "Running CT intrinsics test..."
	./ct_intrinsics_test

# Test with different optimization levels
test-O0: CFLAGS = -O0 -Wall -Wextra -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/wolfssl -DHAVE_CONFIG_H
test-O0: clean ct_test
	@echo "Testing with -O0..."
	./ct_test --quick

test-O3: CFLAGS = -O3 -Wall -Wextra -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/wolfssl -DHAVE_CONFIG_H
test-O3: clean ct_test
	@echo "Testing with -O3..."
	./ct_test --quick

# Test with GCC
test-gcc: CC = gcc
test-gcc: clean ct_test
	@echo "Testing with GCC..."
	./ct_test --quick

clean:
	rm -f $(TARGETS) *.o

help:
	@echo "wolfSSL Constant-Time Test Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build all test programs"
	@echo "  test        - Run full test suite (slow)"
	@echo "  quick-test  - Run quick test suite"
	@echo "  test-O0     - Test with -O0 optimization"
	@echo "  test-O3     - Test with -O3 optimization"
	@echo "  test-gcc    - Test with GCC compiler"
	@echo "  clean       - Remove built files"
	@echo "  help        - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  CC          - C compiler (default: clang)"
	@echo "  WOLFSSL_ROOT - Path to wolfSSL root (default: ../..)"
