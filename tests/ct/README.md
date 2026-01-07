# wolfSSL Constant-Time Testing Framework

This directory contains tools for verifying that wolfSSL's cryptographic
implementations maintain constant-time execution, protecting against
timing-based side-channel attacks.

## Background

Constant-time implementations are critical for cryptographic security. If
cryptographic operations take different amounts of time depending on secret
data (like keys or plaintexts), attackers can potentially recover secrets
by measuring timing variations.

This testing framework is based on research from:
- **Trail of Bits**: [LLVM Constant-Time Support](https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/)
- **DATE 2017 Paper**: "dude, is my code constant time?" by Reparaz, Balasch, and Verbauwhede

## Test Methods

### 1. Static Analysis (`scripts/ct-verify.sh`)

Compiles wolfSSL with Clang and analyzes the generated assembly for:
- Conditional move instructions (`cmov`) - constant-time selection
- Conditional jumps that might indicate timing leaks
- XOR-AND masking patterns (should be preserved)

```bash
# Quick test with O2
./scripts/ct-verify.sh --quick

# Full test across all optimization levels
./scripts/ct-verify.sh

# Test with GCC
./scripts/ct-verify.sh --cc gcc
```

### 2. Dynamic Analysis (`tests/ct/ct_test`)

Uses **dudect** statistical analysis to detect timing leaks at runtime by:
- Running functions with two classes of inputs
- Measuring execution time distributions
- Performing Welch's t-test to detect significant timing differences

```bash
cd tests/ct

# Build the test
make

# Run quick tests
./ct_test --quick

# Run full tests (slower, more thorough)
./ct_test

# List available tests
./ct_test --list

# Run specific test
./ct_test --quick --test 0
```

Or use the wrapper script:
```bash
./scripts/ct-dudect.sh --quick
./scripts/ct-dudect.sh --all-opts  # Test across optimization levels
```

## Functions Tested

| Function | Description | Test Method |
|----------|-------------|-------------|
| `ConstantCompare` | Byte array comparison | dudect |
| `ctMaskSel` | Conditional byte selection | dudect |
| `ctMaskGT` | Greater-than mask generation | dudect |
| `ctMaskEq` | Equality mask generation | dudect |
| `ctMaskCopy` | Conditional memory copy | dudect |
| `sp_cond_swap_ct` | Big integer conditional swap | static analysis |
| `mp_cond_copy` | Multi-precision conditional copy | static analysis |

## Interpreting Results

### Static Analysis

The script reports:
- **Conditional jumps**: May indicate timing leaks if on secret data
- **Conditional moves (cmov)**: Good - constant-time selection
- **XOR-AND patterns**: Should be preserved for CT operations

Note: Some conditional jumps are legitimate (loop bounds, NULL checks).

### Dynamic Analysis (dudect)

- **t-value < 4.5**: No timing leakage detected
- **t-value > 4.5**: Potential timing leakage (needs investigation)

The tool reports "maybe constant time" during testing and gives a final
PASS/FAIL verdict.

## Requirements

- **Clang 18+** or **GCC 13+**
- wolfSSL configured with `--enable-harden`
- POSIX-compatible shell

## Files

```
tests/ct/
├── README.md       # This file
├── ct_test.c       # dudect test harness
├── dudect.h        # dudect library (header-only)
└── Makefile        # Build configuration

scripts/
├── ct-verify.sh    # Static analysis script
└── ct-dudect.sh    # Dynamic analysis wrapper
```

## Configuration Macros

wolfSSL uses these macros for timing resistance:

| Macro | Purpose |
|-------|---------|
| `TFM_TIMING_RESISTANT` | Timing-resistant big integer math |
| `ECC_TIMING_RESISTANT` | Timing-resistant ECC operations |
| `WC_RSA_BLINDING` | RSA blinding for side-channel resistance |
| `WOLFSSL_NO_CT_OPS` | Disables CT operations (NOT recommended) |
| `WC_NO_HARDEN` | Disables all hardening (NOT recommended) |

## Adding New Tests

To add a test for a new CT function:

1. Add a `do_one_computation_<name>` function in `ct_test.c`
2. Add a `prepare_inputs_<name>` function to generate test inputs
3. Add an entry to the `tests[]` array
4. Rebuild and run

## Further Reading

- [Trail of Bits: Constant-Time LLVM Support](https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/)
- [dudect GitHub Repository](https://github.com/oreparaz/dudect)
- [ETH Zürich "Breaking Bad" Study](https://eprint.iacr.org/)
- [wolfSSL Security Best Practices](https://www.wolfssl.com/docs/)
