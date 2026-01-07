#!/bin/bash
#
# ct-dudect.sh - Run dudect-based constant-time tests for wolfSSL
#
# This script builds and runs the dudect-based timing analysis tests
# to verify that wolfSSL's constant-time implementations don't leak
# timing information.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CT_TEST_DIR="$WOLFSSL_ROOT/tests/ct"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run dudect-based constant-time tests for wolfSSL

Options:
    -h, --help      Show this help message
    -q, --quick     Quick mode (fewer measurements)
    -f, --full      Full mode (more thorough, slower)
    -t, --test N    Run only test number N
    -l, --list      List available tests
    --gcc           Use GCC instead of Clang
    --O0            Test with -O0 optimization
    --O3            Test with -O3 optimization
    --all-opts      Test with all optimization levels

Examples:
    $0              # Run quick tests with default compiler
    $0 --full       # Run thorough tests
    $0 --all-opts   # Test across optimization levels
    $0 -t 0         # Run only the first test
EOF
}

# Parse arguments
QUICK_MODE=1
SINGLE_TEST=""
USE_GCC=0
OPT_LEVEL="O2"
ALL_OPTS=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -q|--quick)
            QUICK_MODE=1
            shift
            ;;
        -f|--full)
            QUICK_MODE=0
            shift
            ;;
        -t|--test)
            SINGLE_TEST="$2"
            shift 2
            ;;
        -l|--list)
            cd "$CT_TEST_DIR"
            make -s ct_test 2>/dev/null || true
            if [[ -x ./ct_test ]]; then
                ./ct_test --list
            else
                echo "Available tests:"
                echo "  0: ConstantCompare"
                echo "  1: ctMaskSel"
                echo "  2: ctMaskGT"
                echo "  3: ctMaskEq"
                echo "  4: ctMaskCopy"
            fi
            exit 0
            ;;
        --gcc)
            USE_GCC=1
            shift
            ;;
        --O0)
            OPT_LEVEL="O0"
            shift
            ;;
        --O3)
            OPT_LEVEL="O3"
            shift
            ;;
        --all-opts)
            ALL_OPTS=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

run_tests() {
    local cc=$1
    local opt=$2
    local extra_args=$3

    log_info "Testing with CC=$cc, optimization=-$opt"

    cd "$CT_TEST_DIR"

    # Clean and rebuild
    make clean >/dev/null 2>&1 || true

    CC=$cc CFLAGS="-$opt -Wall -Wextra -I$WOLFSSL_ROOT -I$WOLFSSL_ROOT/wolfssl -DHAVE_CONFIG_H -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT" \
        make ct_test 2>&1 | grep -v "^make"

    if [[ ! -x ./ct_test ]]; then
        log_error "Build failed!"
        return 1
    fi

    # Run tests
    local test_args=""
    if [[ $QUICK_MODE -eq 1 ]]; then
        test_args="--quick"
    fi
    if [[ -n "$SINGLE_TEST" ]]; then
        test_args="$test_args --test $SINGLE_TEST"
    fi

    ./ct_test $test_args $extra_args
    return $?
}

main() {
    echo ""
    echo "==============================================="
    echo "  wolfSSL dudect Constant-Time Test Runner"
    echo "==============================================="
    echo ""

    # Check for required files
    if [[ ! -f "$CT_TEST_DIR/ct_test.c" ]]; then
        log_error "ct_test.c not found in $CT_TEST_DIR"
        exit 1
    fi

    if [[ ! -f "$CT_TEST_DIR/dudect.h" ]]; then
        log_error "dudect.h not found in $CT_TEST_DIR"
        log_info "Downloading dudect.h..."
        curl -sL https://raw.githubusercontent.com/oreparaz/dudect/master/src/dudect.h \
            -o "$CT_TEST_DIR/dudect.h"
    fi

    # Check for config.h (wolfSSL must be configured)
    if [[ ! -f "$WOLFSSL_ROOT/config.h" ]]; then
        log_warning "config.h not found - wolfSSL may not be configured"
        log_info "Running configure..."
        cd "$WOLFSSL_ROOT"
        if [[ -f autogen.sh ]]; then
            ./autogen.sh >/dev/null 2>&1 || true
        fi
        ./configure --enable-harden >/dev/null 2>&1 || {
            log_error "Configure failed"
            exit 1
        }
    fi

    local cc="clang"
    if [[ $USE_GCC -eq 1 ]]; then
        cc="gcc"
    fi

    local failures=0

    if [[ $ALL_OPTS -eq 1 ]]; then
        # Test with multiple optimization levels
        for opt in O0 O1 O2 O3 Os; do
            echo ""
            log_info "========================================"
            log_info "Testing with -$opt"
            log_info "========================================"

            if ! run_tests "$cc" "$opt"; then
                ((failures++))
            fi
        done
    else
        # Single optimization level
        if ! run_tests "$cc" "$OPT_LEVEL"; then
            ((failures++))
        fi
    fi

    echo ""
    echo "==============================================="
    if [[ $failures -eq 0 ]]; then
        log_success "All tests passed!"
    else
        log_error "$failures test configuration(s) failed"
    fi
    echo "==============================================="

    return $failures
}

main "$@"
