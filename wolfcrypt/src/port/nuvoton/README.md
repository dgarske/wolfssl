# Nuvoton (nuvoton) Port

Hardware crypto for the Nuvoton NuMicro **M2354** series (Arm Cortex-M23,
Armv8-M baseline, TrustZone). Written against the
[M2354BSP](https://github.com/OpenNuvoton/M2354BSP) StdDriver and developed on
the [NuMaker-M2354](https://www.nuvoton.com/board/numaker-m2354/)
(M2354KJFAE, 1 MB flash, 256 KB SRAM, 96 MHz).

The part carries three separate blocks, and this port drives all three:

| Block | What it does |
|---|---|
| CRPT | AES, SHA, ECC and RSA accelerator, plus a PRNG |
| TRNG | Entropy source, separate IP, seeds the CRPT PRNG |
| Key Store | Key slots in SRAM, Flash and OTP, used by handle |

The port is a **crypto callback device**: software stays compiled in, and
anything the hardware cannot do is declined and runs in software rather than
failing. Nothing in the wolfSSL core grows a struct member for it - a Key Store
handle rides in the standard `devCtx` of the `Aes` or `ecc_key` it belongs to.

## Enabling

Define `WOLFSSL_NUVOTON_M2354` in `user_settings.h` and add
`wolfcrypt/src/port/nuvoton/*.c` to your project. With nothing else named,
every engine below is offloaded. Name one or more of these instead and only
those are:

```c
#define WOLFSSL_NUVOTON_M2354
/* optional, otherwise all of them */
#define WOLFSSL_NUVOTON_TRNG
#define WOLFSSL_NUVOTON_HASH
#define WOLFSSL_NUVOTON_CIPHER
#define WOLFSSL_NUVOTON_ECC
#define WOLFSSL_NUVOTON_RSA
#define WOLFSSL_NUVOTON_KS
```

`wolfssl/wolfcrypt/port/nuvoton/nuvoton_settings.h` carries the full list,
including `WOLFSSL_NUVOTON_DEVID`, `WOLFSSL_NUVOTON_DMA_BUF_SZ` and
`WOLFSSL_NUVOTON_HW_TIMEOUT`.

The application brings the device up once and then routes work to it by
device id:

```c
wolfCrypt_Init();
wc_NuvotonCryptoCb_RegisterDevice(WOLFSSL_NUVOTON_DEVID);

wc_AesInit(&aes, NULL, WOLFSSL_NUVOTON_DEVID);
wc_ecc_init_ex(&key, NULL, WOLFSSL_NUVOTON_DEVID);
/* or for a whole TLS context: */
wolfSSL_CTX_SetDevId(ctx, WOLFSSL_NUVOTON_DEVID);
```

### The CRPT interrupt is required

The BSP's ECC and RSA drivers block on a flag that only the CRPT interrupt
sets (`ECC_DriverISR` in `Library/StdDriver/src/crypto.c`). Route it:

```c
void CRPT_IRQHandler(void)
{
    ECC_DriverISR(CRPT);
}
...
NVIC_EnableIRQ(CRPT_IRQn);
```

Without the handler every public key call spins to its timeout and returns
`WC_HW_E`. The port reports that as an error rather than falling back to
software on purpose: a missing handler is a wiring mistake, and a silent, very
slow fallback would hide it.

## What is offloaded

| Engine | Operations | Notes |
|---|---|---|
| TRNG | `wc_GenerateSeed`, `WC_ALGO_TYPE_RNG` | Also wired into the `wc_GenerateSeed` chain in `wolfcrypt/src/random.c`, so a `WC_RNG` built with `INVALID_DEVID` still gets entropy |
| SHA | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | One engine call per message, see below |
| AES | ECB, CBC, CTR | 128, 192 and 256 bit, whole blocks |
| ECC | ECDSA sign and verify, ECDH, key generation | P-192, P-224, P-256, P-384, P-521, Brainpool P-256/384/512 |
| RSA | Public and private modular exponentiation | 1024, 2048, 3072 and 4096 bit |
| Key Store | AES and ECC private keys by handle | `wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h` |

Declined, and therefore run in software:

- **AES-GCM and AES-CCM.** The engine does both, but not as a plain DMA round:
  they want the message laid out in the GCM packet format the TRM describes
  plus a feedback buffer at `AES_FBADDR`. That is another thousand lines in
  Nuvoton's own mbedTLS layer, and it is not something to write blind. Until it
  has been checked on silicon, declining means AES-GCM produces a correct tag
  from software rather than an unverified one from hardware.
- **AES-CTR that does not start on a block boundary.** wolfCrypt tracks the
  unused bytes of the current key stream block in `aes->left`; the engine has
  no way to be told to start part way into a block.
- **Truncated SHA-512.** SHA-512/224 and SHA-512/256 start from different
  initial values and the engine only does full SHA-512.
- **Curves the engine does not have,** and RSA key sizes other than the four
  above.
- **The empty message.** The SHA result register is only written by a DMA
  round, and a zero length round does not start one.

## Key Store

A key written to the store gets a slot, and from then on the application uses
the handle. The key material never enters wolfCrypt memory again:

```c
wc_NuvotonKsKey ksKey;
Aes aes;

wc_NuvotonKs_Write(&ksKey, WC_NUVOTON_KS_MEM_SRAM, WC_NUVOTON_KS_OWNER_AES,
                   256, keyBytes, sizeof(keyBytes), 0 /* not readable */);

wc_AesInit(&aes, NULL, WOLFSSL_NUVOTON_DEVID);
wc_NuvotonKs_SetAesKey(&aes, &ksKey);
wc_AesSetIV(&aes, iv);
wc_AesCbcEncrypt(&aes, out, in, sizeof(in));
```

`wc_NuvotonKs_SetEccKey()` does the same for an ECDH private key. The handle
has to outlive the object that points at it.

:warning: **OTP slots cannot be rewritten.** A mistake there is permanent.

:warning: `KS_EraseKey()` in the BSP writes `KS_SRAM` into the metadata itself,
so only a volatile slot can be cleared. Flash and OTP keys are retired with
`wc_NuvotonKs_Revoke()`, which also cannot be undone.

## TrustZone

`CRPT`, `TRNG` and the Key Store are secure-only peripherals in the default SCU
partition, and `M2354.h` has no `KS_NS` alias at all. So where wolfCrypt runs
decides how it reaches them, and the port is built for either:

| Macro | wolfCrypt runs | How it reaches the hardware |
|---|---|---|
| `WOLFSSL_NUVOTON_SECURE` (default) | Secure world, which is also where a non-TrustZone application runs | `nuvoton_hw.c` calls the BSP drivers directly |
| `WOLFSSL_NUVOTON_NSC` | Non-secure world | `cmse_nonsecure_entry` veneers in a secure partition |

Everything the port does to the hardware goes through the `wc_nuvoton_hw_*`
calls in `nuvoton_hw.h`, and no other file in the port includes a BSP header.
That leaves one seam to move between the two, and the rest of the port is
byte-identical either way.

`IDE/Nuvoton/M2354/secure/nuvoton_nsc.c` is the secure half: one veneer per
call, each copying the request into secure memory and validating every pointer
with `cmse_check_address_range()` before the driver sees it.

## Hashing, and why each context saves its message

The SHA engine can cascade a message across several DMA rounds, but it holds
that partial state in its own registers and offers no way to save and restore
it, so only one cascade can be open at a time. wolfCrypt interleaves hashes
freely - a TLS handshake runs the transcript hash against the record MAC, and
`wc_Sha256Copy` forks the transcript - so a cascade cannot be tied to a
wolfCrypt hash object. Nuvoton's own mbedTLS layer has the same limitation and
does not guard against it.

Each context therefore accumulates its message in its own buffer and hashes it
in one engine call at `final()`, which is what the Versal Gen2 ASU port does
for the same reason. The cost is memory proportional to the largest message
hashed; `WOLFSSL_HASH_KEEP` is required and the port `#error`s without it.

## DMA addressing

CRPT DMA reads and writes only word-aligned addresses in the `0x2xxxxxxx` SRAM
region - Nuvoton states this in the BSP's own
`Library/CryptoAccelerator/aes_alt.c`. AES stages anything else through a
bounce buffer sized by `WOLFSSL_NUVOTON_DMA_BUF_SZ` (six blocks by default).
SHA does not: a whole message will not fit, and staging it would need a cascade
and therefore exclusive use of the engine across calls, so a message the engine
cannot address is declined to software instead. In practice a message coming
from `XMALLOC` on this part always qualifies.

## Multi-threading

The CRPT has one usable channel and the port serializes every operation on
`wolfSSL_CryptHwMutexLock()`. A build with `SINGLE_THREADED` gets that for
free.

## Example project

`IDE/Nuvoton/M2354/` builds `wolfcrypt_test` and the benchmark for the
NuMaker-M2354, including the CRPT interrupt handler and a `user_settings.h` to
start from. See its README for the build and flash steps.

## Status

Every source in this port compiles clean for Cortex-M23 with
`arm-none-eabi-gcc -Wall -Wextra -Werror` against the real BSP, in both the
secure and the non-secure configuration, and the secure configuration links to
a complete image. **Nothing has been run on silicon yet**: the `wolfcrypt_test`
result, the benchmark table below and the per-engine fallback behaviour all
wait on hardware.

## Benchmarks

To be filled in from `IDE/Nuvoton/M2354` on a NuMaker-M2354.

# Support

For questions please email support@wolfssl.com
