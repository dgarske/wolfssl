# RealTek AmebaPro2 (RTL8735B) HUK Port

Binds wolfCrypt keys to the RTL8735B silicon Hardware Unique Key (HUK) through
the AmebaPro2 HAL crypto engine, via the wolfCrypt crypto-callback (CryptoCb)
framework. A 256-bit "seed" is run through the HAL HKDF key-ladder against the
HUK to land a device-bound working key in a secure key-storage slot; AES
(GCM/ECB/CBC/CTR) then runs from that slot and the working key never enters
software. This mirrors the vendor-neutral DHUK device the STM32 port provides
(`wc_Stm32_DhukRegister`) and reuses the same generic `WOLFSSL_DHUK` plumbing
(`wc_ecc_import_wrapped_private`, the `ecc_key` seed/wrapped-key fields).

## Hardware

RTL8735B / AmebaPro2 security blocks used by this port (from the
`Ameba-AIoT/nuwa_hal_realtek` SDK, `rtl8735b` branch, headers under
`ameba/amebapro2/source/fwlib/rtl8735b/include/`):

- HUK in OTP: `SB_OTP_HIGH_VAL_HUK1` (0x21), `HUK2` (0x22), `HUK_RMA` (0x2F).
- HKDF key-ladder in secure RAM: `hal_hkdf_hmac_sha256_secure_init`,
  `hal_hkdf_extract_secure_all`, `hal_hkdf_expand_secure_all` -- derive the HUK
  into a secure key-storage slot without exposing the key to software.
- AES secure-key ops that reference the derived slot by number:
  `hal_crypto_aes_ecb_sk_init`, `hal_crypto_aes_gcm_sk_init` (key never leaves
  hardware).
- ECDSA (`hal_ecdsa.h`) and OTP-resident ECDSA keys (`hal_otp_ecdsa_key_*`) for
  the HUK-bound sign path (Stage 3, in progress).
- TRNG (`hal_trng.h`); the `ameba-zephyr-pro2-platform` repo provides a Zephyr
  entropy driver (`entropy_amebapro2.c`, DT `realtek,amebapro2-trng`) that feeds
  wolfCrypt's `wc_GenerateSeed` via `sys_rand_get`.

## Enabling

```c
#define WOLFSSL_REALTEK_HUK   /* enable the AmebaPro2 HUK device */
#define WOLF_CRYPTO_CB        /* required -- HUK routes through crypto callbacks */
```

`WOLFSSL_REALTEK_HUK` implies `WOLFSSL_DHUK` (the generic seed/wrapped-key
plumbing). Set these in `user_settings.h`. The application/board CMake must add
the AmebaPro2 HAL include directory (e.g.
`.../fwlib/rtl8735b/include/`) to the wolfSSL library include path so this port
can include `hal_crypto.h` and `hal_hkdf.h` (plus `hal_ecdsa.h` once the ECDSA
sign path lands).

Configurable (override in `user_settings.h` before including wolfSSL):

| Macro                          | Default | Meaning                              |
|--------------------------------|---------|--------------------------------------|
| `WC_HUK_DEVID`                 | 809     | CryptoCb device id (STM32 DHUK is 808) |
| `WC_AMEBAPRO2_HUK_SK_IDX`      | 1       | Secure-key slot holding the HUK (HUK1) |
| `WC_AMEBAPRO2_HKDF_PRK_IDX`    | 3       | Intermediate HKDF PRK slot           |
| `WC_AMEBAPRO2_DERIVED_WB_IDX`  | 4       | Derived working-key slot (AES uses it) |
| `WC_AMEBAPRO2_HKDF_CRYPTO_SEL` | 0       | `crypto_sel` for the secure HKDF init |

## API

```c
#include <wolfssl/wolfcrypt/port/realtek/amebapro2.h>

/* One-time: register the AmebaPro2 HUK crypto-callback device. */
wc_AmebaPro2_HukRegister(WC_HUK_DEVID);

/* AES / GCM: enable via devId at init, then pass the 256-bit seed as the key.
 * The seed is HKDF input that diversifies the HUK -- it is NOT the AES key. */
Aes aes;
byte seed[32];     /* per-purpose derivation seed (need not be secret) */
wc_AesInit(&aes, NULL, WC_HUK_DEVID);
wc_AesGcmSetKey(&aes, seed, 32);
wc_AesGcmEncrypt(&aes, ct, pt, ptSz, iv, 12, tag, tagSz, aad, aadSz); /* full GCM */
wc_AesFree(&aes);

/* AES-ECB / AES-CBC follow the same pattern (wc_AesSetKey + wc_AesEcb*/
/* wc_AesCbc* with devId = WC_HUK_DEVID). */

wc_AmebaPro2_HukUnRegister(WC_HUK_DEVID);
```

The seed maps to a device-bound working key as:
HUK (slot `WC_AMEBAPRO2_HUK_SK_IDX`) -> `hal_hkdf_extract_secure_all` -> PRK slot
-> `hal_hkdf_expand_secure_all` -> working key in `WC_AMEBAPRO2_DERIVED_WB_IDX`
-> `hal_crypto_aes_gcm_sk_init` / `hal_crypto_aes_ecb_sk_init`. The derive and
the AES op run under one crypto-mutex hold; the working key never enters
software. Identical seed -> identical working key (deterministic, so GMAC
verifies and AES round-trips); a wrong seed yields a different key (GCM decrypt
returns `AES_GCM_AUTH_E`).

ECDSA sign mirrors this and is in progress (Stage 3): import the HUK-bound
private key (either wrapped-scalar via `wc_ecc_import_wrapped_private`, or an
OTP-resident key selected by index), init the key with
`wc_ecc_init_ex(&key, NULL, WC_HUK_DEVID)`, then call `wc_ecc_sign_hash()`.

## Notes / limitations

- The HAL GCM path assumes a 96-bit (12-byte) IV (standard J0). A non-12-byte
  IV returns a hard error (not a software fallback, which would key off the seed
  rather than the device-bound key).
- AES-CBC and AES-CTR chain in software over single-block
  `hal_crypto_aes_ecb_sk_*` calls because the HAL exposes no CBC/CTR secure-key
  variant; the key still stays in hardware. CTR maintains the wolfCrypt counter
  state (`aes->reg`/`tmp`/`left`) so partial blocks continue across calls.
- The HAL crypto engine DMAs its buffers on 32-byte (cache-line) boundaries and
  rejects an unaligned GCM iv/aad. The port stages key/iv/aad/tag on aligned
  temporaries and bounces unaligned in/out through aligned buffers, so callers
  need not align.
- Each operation derives the working key from the Aes' own `devKey` seed under
  the crypto mutex (no shared port global), so concurrent `Aes` objects are
  safe.
- `--enable-amebapro2` builds a host compile-test only: it swaps the HAL headers
  for `amebapro2_shim.h` (sentinel stubs, no real crypto) to exercise the
  crypto-callback dispatch and build wiring without the vendor SDK. All
  functional validation requires RTL8735B hardware.

## Status

Validated on RTL8735B silicon (both the RealTek FreeRTOS SDK app and a Zephyr
image): registration, AES-GCM (encrypt / deterministic tag / decrypt-verify /
round-trip / wrong-seed -> `AES_GCM_AUTH_E`), AES-ECB and AES-CBC all pass.

- Stage 0 (skeleton, build wiring, host compile-test): done.
- Stage 1 (HUK key-ladder + full AES-GCM): done, validated on hardware.
- Stage 2 (AES-ECB / AES-CBC / AES-CTR): done, validated on hardware.
- Stage 3 (ECDSA sign, wrapped-scalar then OTP-resident): follow-on, not yet
  implemented (`WC_PK_TYPE_ECDSA_SIGN` returns `NOT_COMPILED_IN`).

## Benchmarks (software crypto baseline)

`wolfcrypt_test` (full self-test, all PASS) and `wolfcrypt_benchmark` were run on
the RTL8735B EVB to validate the core library and toolchain on this target. The
figures below are **pure software wolfCrypt** -- they are NOT the HUK device
(which routes AES through the silicon engine for HUK-derived keys); they serve as
a reference baseline and to size the benefit of hardware offload.

- Target: RTL8735B "KM4" Arm Cortex-M33 (ARMv8-M Mainline, TrustZone + DSP) at
  500 MHz (`CPU_CLK`); DDR at 533 MHz.
- Toolchain / build: RealTek ASDK 10.3.0 (GCC 10.3.0), SDK default `-Os`,
  FreeRTOS, `WOLFCRYPT_ONLY`, `SINGLE_THREADED`, big-integer math via the generic
  `WOLFSSL_SP_MATH_ALL` (portable C, no Cortex-M assembly), `BENCH_EMBEDDED`.
- Build options live with the SDK example (not in the wolfSSL tree):
  `component/example/wolfcrypt_test/{user_settings.h, wolfcrypt_test.cmake,
  main.c}` of the AmebaPro2 FreeRTOS SDK. The RNG is seeded from the SDK
  `rtw_get_random_bytes`; `current_time()` uses `hal_read_systime_us()`.

Symmetric / hash (higher is better):

| Algorithm           | Throughput |
|---------------------|------------|
| AES-128-CBC enc/dec | 9.55 / 9.67 MiB/s |
| AES-256-CBC enc/dec | 7.25 / 7.02 MiB/s |
| AES-128-GCM enc/dec | 5.35 / 5.33 MiB/s |
| AES-256-GCM enc/dec | 4.53 / 4.52 MiB/s |
| AES-128-CTR         | 9.75 MiB/s |
| AES-128-ECB enc/dec | 10.42 / 10.56 MiB/s |
| AES-CCM enc/dec     | 4.73 / 4.65 MiB/s |
| GMAC (4-bit table)  | 13.43 MiB/s |
| AES-128-CMAC        | 8.84 MiB/s |
| ChaCha20            | 24.79 MiB/s |
| ChaCha20-Poly1305   | 15.83 MiB/s |
| Poly1305            | 64.77 MiB/s |
| SHA-1               | 29.19 MiB/s |
| SHA-256             | 10.94 MiB/s |
| SHA-512             | 7.29 MiB/s |
| SHA3-256            | 6.61 MiB/s |
| HMAC-SHA256         | 10.85 MiB/s |

Public key (higher is better):

| Operation             | Rate |
|-----------------------|------|
| RSA-2048 public       | 214.7 ops/s |
| RSA-2048 private      | 6.14 ops/s |
| RSA-2048 key gen      | 0.40 ops/s |
| DH-2048 key gen/agree | 17.67 / 15.23 ops/s |
| ECDSA P-256 sign/verify | 40.03 / 29.81 ops/s |
| ECDHE P-256 agree     | 40.69 ops/s |
| Curve25519 key gen/agree | 414.8 / 419.4 ops/s |
| Ed25519 sign/verify   | 788.3 / 397.0 ops/s |

The tables above are the portable-C baseline. The assembly backends below raise
these substantially. Curve25519/Ed25519 already use the dedicated
`curve25519.c`/`ed25519.c` fast code.

## Optimizations (measured on RTL8735B @ 500 MHz, -Os)

Two wolfCrypt assembly backends apply to this Cortex-M33 and were validated on
hardware (both keep `wolfcrypt_test` all-PASS). Neither needs wolfSSL source
changes -- they are build-config selections plus adding the relevant asm files.

### 1. Public key -- `sp_cortexm.c` (Thumb-2/DSP single-precision)

Enable with `WOLFSSL_SP_ARM_CORTEX_M_ASM` + `WOLFSSL_HAVE_SP_RSA` +
`WOLFSSL_HAVE_SP_ECC` + `WOLFSSL_HAVE_SP_DH`, and add `wolfcrypt/src/sp_cortexm.c`
to the build (alongside the generic `sp_int.c` for sizes without an asm path).

| Operation              | Generic C | sp_cortexm | Speedup |
|------------------------|-----------|------------|---------|
| ECC P-256 key gen      | 40.7      | 541.2 ops/s | 13.3x |
| ECDSA P-256 sign       | 40.0      | 427.6 ops/s | 10.7x |
| ECDSA P-256 verify     | 29.8      | 292.7 ops/s | 9.8x  |
| ECDHE P-256 agree      | 40.7      | 318.1 ops/s | 7.8x  |
| RSA-2048 public        | 214.7     | 618.4 ops/s | 2.9x  |
| RSA-2048 private       | 6.14      | 19.0 ops/s  | 3.1x  |
| DH-2048 agree          | 15.2      | 38.3 ops/s  | 2.5x  |

### 2. Symmetric -- Thumb-2 asm (`port/arm/thumb2-*-asm.S`)

Enable with `WOLFSSL_ARMASM` + `WOLFSSL_ARMASM_THUMB2` +
`WOLFSSL_ARMASM_NO_HW_CRYPTO` + `WOLFSSL_ARMASM_NO_NEON` + `WOLFSSL_ARM_ARCH=7`,
and add `thumb2-aes-asm.S`, `thumb2-sha256-asm.S`, `thumb2-sha512-asm.S`,
`thumb2-sha3-asm.S`, `thumb2-chacha-asm.S`, `thumb2-poly1305-asm.S`.
`WOLFSSL_ARMASM` is a global switch, so provide the `.S` for every covered
module. (Curve25519/Ed25519 also have Thumb-2 asm but their `ge_operations.c`
integration assumes 64-bit and was left on the C path here.)

| Algorithm           | Generic C | Thumb-2 asm | Speedup |
|---------------------|-----------|-------------|---------|
| AES-128-CBC enc     | 9.55      | 20.85 MiB/s | 2.2x |
| AES-128-ECB enc     | 10.42     | 20.82 MiB/s | 2.0x |
| AES-128-CTR         | 9.75      | 20.47 MiB/s | 2.1x |
| AES-128-GCM enc     | 5.35      | 10.30 MiB/s | 1.9x |
| GMAC                | 13.43     | 20.81 MiB/s | 1.5x |
| AES-128-CMAC        | 8.84      | 14.67 MiB/s | 1.7x |
| ChaCha20            | 24.79     | 46.44 MiB/s | 1.9x |
| ChaCha20-Poly1305   | 15.83     | 25.38 MiB/s | 1.6x |
| SHA-256             | 10.94     | 17.83 MiB/s | 1.6x |
| SHA3-256            | 6.61      | 8.64 MiB/s  | 1.3x |
| HMAC-SHA256         | 10.85     | 17.66 MiB/s | 1.6x |

### Note on hardware offload

For AES, hashing and ECDSA the RTL8735B has a dedicated crypto engine (the HAL
`hal_crypto_*` / `hal_ecdsa` blocks this HUK port already uses for HUK-derived
keys). A general (any-key) HW crypto-callback port over that engine would beat
the Thumb-2 software figures above and is the recommended production path for
symmetric throughput; the Thumb-2 asm is the portable software fallback. The
`sp_cortexm.c` PK speedup is worth taking regardless, since it needs no silicon
support.
