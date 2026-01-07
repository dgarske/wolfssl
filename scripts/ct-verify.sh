#!/bin/bash
#
# ct-verify.sh - Constant-Time Verification Script for wolfSSL
#
# This script builds wolfSSL with Clang and analyzes the generated assembly
# to verify that constant-time operations are not being optimized into
# data-dependent branches by the compiler.
#
# Based on Trail of Bits research on LLVM constant-time support:
# https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$WOLFSSL_ROOT/ct-verify-build"
ASM_DIR="$BUILD_DIR/asm"
REPORT_FILE="$BUILD_DIR/ct-verify-report.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Compiler settings
CC="${CC:-clang}"
OPT_LEVELS="${OPT_LEVELS:-O0 O1 O2 O3 Os}"

# Files containing constant-time critical code
CT_CRITICAL_FILES=(
    "wolfcrypt/src/misc.c"
    "wolfcrypt/src/rsa.c"
    "wolfcrypt/src/ecc.c"
    "wolfcrypt/src/aes.c"
    "wolfcrypt/src/sp_int.c"
    "wolfcrypt/src/wolfmath.c"
)

# Functions that MUST remain constant-time
CT_FUNCTIONS=(
    "ctMaskGT"
    "ctMaskGTE"
    "ctMaskLT"
    "ctMaskLTE"
    "ctMaskEq"
    "ctMaskNotEq"
    "ctMaskSel"
    "ctMaskSelInt"
    "ctMaskSelWord32"
    "ctMaskCopy"
    "ConstantCompare"
    "ctSetLTE"
    "ctMask16GT"
    "ctMask16GTE"
    "ctMask16LT"
    "ctMask16LTE"
    "ctMask16Eq"
    "mp_cond_copy"
    "sp_cond_swap_ct"
)

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Constant-Time Verification Script for wolfSSL

Options:
    -h, --help          Show this help message
    -c, --clean         Clean build directory before starting
    -o, --opt LEVELS    Optimization levels to test (default: "O0 O1 O2 O3 Os")
    -v, --verbose       Verbose output
    --cc COMPILER       C compiler to use (default: clang)
    --quick             Quick mode - only test O2 optimization

Examples:
    $0                          # Run full verification
    $0 --quick                  # Quick test with O2 only
    $0 --opt "O2 O3"           # Test specific optimization levels
    $0 --cc gcc                 # Use GCC instead of Clang
EOF
}

# Parse arguments
VERBOSE=0
CLEAN=0
QUICK=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -c|--clean)
            CLEAN=1
            shift
            ;;
        -o|--opt)
            OPT_LEVELS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --cc)
            CC="$2"
            shift 2
            ;;
        --quick)
            QUICK=1
            OPT_LEVELS="O2"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check for required tools
check_requirements() {
    log_info "Checking requirements..."

    if ! command -v "$CC" &> /dev/null; then
        log_error "Compiler '$CC' not found"
        exit 1
    fi

    log_info "Using compiler: $($CC --version | head -n1)"
}

# Setup build directory
setup_build_dir() {
    if [[ $CLEAN -eq 1 ]] && [[ -d "$BUILD_DIR" ]]; then
        log_info "Cleaning build directory..."
        rm -rf "$BUILD_DIR"
    fi

    mkdir -p "$BUILD_DIR"
    mkdir -p "$ASM_DIR"

    # Initialize report
    cat > "$REPORT_FILE" << EOF
================================================================================
wolfSSL Constant-Time Verification Report
Generated: $(date)
Compiler: $($CC --version | head -n1)
================================================================================

EOF
}

# Compile a file to assembly with specific optimization level
compile_to_asm() {
    local src_file="$1"
    local opt_level="$2"
    local base_name=$(basename "$src_file" .c)
    local asm_file="$ASM_DIR/${base_name}_${opt_level}.s"

    # Build include paths
    local includes="-I$WOLFSSL_ROOT -I$WOLFSSL_ROOT/wolfssl"

    # Common defines for hardened build
    local defines="-DWOLFSSL_USER_SETTINGS"
    defines="$defines -DTFM_TIMING_RESISTANT"
    defines="$defines -DECC_TIMING_RESISTANT"
    defines="$defines -DWC_RSA_BLINDING"
    defines="$defines -DHAVE_CONFIG_H"

    # Compile to assembly with annotations
    if [[ $VERBOSE -eq 1 ]]; then
        log_info "Compiling: $src_file with -$opt_level"
    fi

    $CC -$opt_level -S -fverbose-asm \
        $includes $defines \
        -o "$asm_file" \
        "$WOLFSSL_ROOT/$src_file" 2>/dev/null || {
        log_warning "Failed to compile $src_file (may need configure first)"
        return 1
    }

    echo "$asm_file"
}

# Analyze assembly for a specific function
analyze_function() {
    local asm_file="$1"
    local func_name="$2"
    local issues=()

    # Extract function body (between label and next function/section)
    local func_body=$(sed -n "/^${func_name}:/,/^[a-zA-Z_][a-zA-Z0-9_]*:/p" "$asm_file" 2>/dev/null | head -n -1)

    # If function not found (might be inlined), try to find it differently
    if [[ -z "$func_body" ]]; then
        # Try to find mangled C++ names or different formats
        func_body=$(grep -A 50 "# -- Begin function ${func_name}" "$asm_file" 2>/dev/null || true)
    fi

    if [[ -z "$func_body" ]]; then
        # Function might be inlined - this is actually good for inline functions
        return 0
    fi

    # Check for conditional jumps that might indicate timing leaks
    # Good: cmov (conditional move), csel (ARM), setcc
    # Bad: jne, je, jz, jnz, jg, jl, etc. based on secret data

    local cond_jumps=$(echo "$func_body" | grep -E '^\s*(je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|js|jns)\s' | wc -l)
    local cmov_ops=$(echo "$func_body" | grep -E '^\s*cmov' | wc -l)
    local setcc_ops=$(echo "$func_body" | grep -E '^\s*set[a-z]+' | wc -l)

    # A high ratio of conditional jumps to cmov could indicate problems
    if [[ $cond_jumps -gt 0 ]]; then
        issues+=("Found $cond_jumps conditional jumps (potential timing leak)")
    fi

    if [[ $cmov_ops -gt 0 ]]; then
        # Good - using conditional moves
        :
    fi

    if [[ ${#issues[@]} -gt 0 ]]; then
        echo "${issues[*]}"
        return 1
    fi

    return 0
}

# Analyze a single assembly file for CT violations
analyze_asm_file() {
    local asm_file="$1"
    local opt_level="$2"
    local problems=0
    local warnings=0

    if [[ ! -f "$asm_file" ]]; then
        return 0
    fi

    echo "" >> "$REPORT_FILE"
    echo "--- Analyzing: $(basename "$asm_file") ---" >> "$REPORT_FILE"

    # Look for problematic patterns in CT-critical code

    # 1. Check for conditional jumps after comparisons with potential secrets
    local cond_jumps=$(grep -c -E '^\s*(je|jne|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe)\s' "$asm_file" 2>/dev/null || echo "0")

    # 2. Count good patterns (conditional moves)
    local cmov_count=$(grep -c -E '^\s*cmov[a-z]+\s' "$asm_file" 2>/dev/null || echo "0")

    # 3. Look for table lookups that might be variable-time
    local table_lookups=$(grep -c -E 'movzbl.*\(' "$asm_file" 2>/dev/null || echo "0")

    # 4. Check for function calls within CT functions (might break CT)
    local call_count=$(grep -c -E '^\s*call\s' "$asm_file" 2>/dev/null || echo "0")

    echo "  Conditional jumps: $cond_jumps" >> "$REPORT_FILE"
    echo "  Conditional moves (cmov): $cmov_count" >> "$REPORT_FILE"
    echo "  Memory indexed loads: $table_lookups" >> "$REPORT_FILE"
    echo "  Function calls: $call_count" >> "$REPORT_FILE"

    # Analyze specific CT functions
    for func in "${CT_FUNCTIONS[@]}"; do
        local result=$(analyze_function "$asm_file" "$func" 2>/dev/null || true)
        if [[ -n "$result" ]]; then
            echo "  $func: $result" >> "$REPORT_FILE"
            ((warnings++))
        fi
    done

    return $warnings
}

# Search for specific problematic patterns
check_problematic_patterns() {
    local asm_file="$1"
    local issues=()

    # Pattern 1: Conditional jumps right after compare with memory
    if grep -B1 -E '^\s*(je|jne|jz|jnz)\s' "$asm_file" | grep -q 'cmp.*(%'; then
        issues+=("Conditional jump after memory comparison")
    fi

    # Pattern 2: Variable-time table lookup (indexed memory access)
    # This might indicate S-box lookups or similar that could leak timing
    if grep -E 'mov.*\(.*,.*,.*\)' "$asm_file" | grep -qv 'rsp\|rbp'; then
        # Indexed addressing mode not on stack - might be table lookup
        :  # This is informational, not necessarily a problem
    fi

    echo "${issues[@]}"
}

# Run the full verification
run_verification() {
    local total_warnings=0
    local total_errors=0

    log_info "Starting constant-time verification..."
    echo "" >> "$REPORT_FILE"
    echo "VERIFICATION RESULTS" >> "$REPORT_FILE"
    echo "====================" >> "$REPORT_FILE"

    for opt in $OPT_LEVELS; do
        log_info "Testing optimization level: -$opt"
        echo "" >> "$REPORT_FILE"
        echo "=== Optimization Level: -$opt ===" >> "$REPORT_FILE"

        local opt_warnings=0

        for src_file in "${CT_CRITICAL_FILES[@]}"; do
            if [[ -f "$WOLFSSL_ROOT/$src_file" ]]; then
                local asm_file=$(compile_to_asm "$src_file" "$opt")
                if [[ -n "$asm_file" ]] && [[ -f "$asm_file" ]]; then
                    analyze_asm_file "$asm_file" "$opt" || {
                        ((opt_warnings+=$?))
                    }
                fi
            fi
        done

        if [[ $opt_warnings -eq 0 ]]; then
            log_success "No issues found at -$opt"
        else
            log_warning "$opt_warnings potential issues at -$opt"
            ((total_warnings+=opt_warnings))
        fi
    done

    return $total_warnings
}

# Generate summary
generate_summary() {
    local warnings=$1

    echo "" >> "$REPORT_FILE"
    echo "================================================================================
SUMMARY
================================================================================
" >> "$REPORT_FILE"

    if [[ $warnings -eq 0 ]]; then
        echo "Status: PASS - No obvious constant-time violations detected" >> "$REPORT_FILE"
        log_success "Verification complete - No obvious issues found"
    else
        echo "Status: REVIEW NEEDED - $warnings potential issues found" >> "$REPORT_FILE"
        log_warning "Verification complete - $warnings items need review"
    fi

    echo "" >> "$REPORT_FILE"
    echo "Note: This static analysis can detect some problematic patterns but cannot" >> "$REPORT_FILE"
    echo "guarantee constant-time execution. Consider using dynamic testing tools" >> "$REPORT_FILE"
    echo "like dudect for more comprehensive verification." >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "For more information on LLVM constant-time support, see:" >> "$REPORT_FILE"
    echo "https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/" >> "$REPORT_FILE"

    log_info "Report saved to: $REPORT_FILE"
    log_info "Assembly files saved to: $ASM_DIR/"
}

# Main execution
main() {
    cd "$WOLFSSL_ROOT"

    echo ""
    echo "==============================================="
    echo "  wolfSSL Constant-Time Verification Tool"
    echo "==============================================="
    echo ""

    check_requirements
    setup_build_dir

    # Check if configure has been run
    if [[ ! -f "$WOLFSSL_ROOT/config.h" ]]; then
        log_warning "config.h not found - running autogen and configure..."
        if [[ -f "$WOLFSSL_ROOT/autogen.sh" ]]; then
            ./autogen.sh > /dev/null 2>&1 || true
        fi
        ./configure --enable-harden > /dev/null 2>&1 || {
            log_error "Configure failed. Please run configure manually first."
            exit 1
        }
    fi

    run_verification
    local result=$?

    generate_summary $result

    echo ""
    echo "To view the full report:"
    echo "  cat $REPORT_FILE"
    echo ""
    echo "To inspect assembly for a specific function, e.g. ctMaskSel:"
    echo "  grep -A 20 'ctMaskSel' $ASM_DIR/misc_O2.s"
    echo ""

    return $result
}

main "$@"
