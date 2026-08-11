# wolfSSL NXP Hardware Acceleration Ports

wolfSSL supports hardware acceleration on NXP DCP, LTC (KSDK), LPC55S69, and SE050.

## NXP LPC55S69

The LPC55S69 is a general purpose edge computing device, with dual ARM
Cortex-M33 cores running up to 150 MHz, 640/320 KB internal flash/ram,
TrustZone-M, a DSP accelerator, and extensive cryptographic acceleration.

wolfSSL supports the following hardware acceleration on the LPC55S69:
- TRNG
- HashCrypt (Hash/AES Crypto Engine)
  - AES (128, 192, 256) encrypt/decrypt
    - AES-CBC, AES-ECB, AES-CTR, AES-OFB, AES-CFB
  - SHA-1, SHA-256
- CASPER (Asymmetric Crypto Accelerator)
  - RSA verify/encrypt/decrypt (up to 4096-bit, public key only)

### LPC55S69 Hardware Acceleration Caveats

The following caveats should be noted about the LPC55S69 hardware acceleration:
- AES-CTR mode fails when the counter wraps from all FF's to 0.  User should
ensure this never happens, by properly managing the iv/counter in use.
- AES-CFB and AES-OFB only support full 16-byte blocks and multiples thereof.
Encrypt/Decrypt requests of other sizes will fail.
- RSA acceleration is only supported for public keys.  Private key operations
will use a fully software implementation.
- When the HashCrypt engine is in use for SHA-1 or SHA-256, it must not be
interrupted with another hash request or an AES request.  The hash must be
completed before another operation is requested.

### wolfSSL LPC55S69 Hardware Acceleration Enable

To enable only the TRNG, define the following symbol:

**`WOLFSSL_NXP_RNG_1`**

To enable all LPC55S69 hardware acceleration, including the TRNG,
define the following symbol:

**`WOLFSSL_NXP_LPC55S6X`**

NOTE: Both can be defined with no problem.

## NXP SE050

For details on wolfSSL integration with NXP SE050,
see [README_SE050.md](./README_SE050.md).

## NXP EdgeLock Secure Enclave (ELE)

For i.MX 8ULP / i.MX 93 / i.MX 95, where NXP replaced CAAM with the EdgeLock
Secure Enclave. Implemented as a crypto callback device.

### Enable

```sh
./configure --enable-ele
```

Defines `WOLFSSL_NXP_ELE` and turns on crypto callbacks. Register the device
before use:

```c
wolfCrypt_Init();   /* required: marks the callback table slots free */
wc_EleCryptoCb_RegisterDevice(WOLFSSL_NXP_ELE_DEVID);
wc_InitRng_ex(&rng, NULL, WOLFSSL_NXP_ELE_DEVID);
```

`ele_settings.h` also sets `WC_USE_DEVID`, so the stock `wolfcrypt/test` and
`wolfcrypt/benchmark` route to the device without source changes.

### Supported

| Feature | Status | Interface |
|---|---|---|
| TRNG / RNG seed | Supported | `/dev/hwrng` (`ele-trng`) |
| Hash, AES, HMAC/CMAC, PK | Not yet | enclave HSM interface |

Everything unimplemented returns `CRYPTOCB_UNAVAILABLE`, so wolfCrypt falls
back to software automatically.

### Configuration macros

| Macro | Default | Purpose |
|---|---|---|
| `WOLFSSL_NXP_ELE` | off | Enable the port |
| `WOLFSSL_NXP_ELE_DEVID` | `0x454C45` | Crypto callback device id |
| `WOLFSSL_NXP_ELE_TRNG_DEVICE` | `/dev/hwrng` | Enclave TRNG character device |
| `WOLFSSL_NXP_ELE_TRNG` | on | Build the TRNG support |
| `WOLFSSL_NXP_ELE_NO_DEVID` | off | Do not set `WC_USE_DEVID` |

### Notes

The enclave TRNG is reached through the Linux hwrng framework, so no NXP
userspace library is required. Confirm the backing source on the target:

```sh
cat /sys/class/misc/hw_random/rng_current      # -> ele-trng
```

The node is root-only by default; a non-root process gets `WC_HW_E`.

The enclave exposes **no post-quantum algorithms** to userspace. Its value is
key storage, attestation and classical crypto - ML-KEM and ML-DSA run on the
CPU.

Reaching the enclave's HSM interface (`/dev/hsm0_ch0`) needs NXP's
`imx-secure-enclave` userspace library **and** a kernel providing NXP's
downstream `ele_mu` driver. Kernels using the upstream `fsl-se` driver
(`CONFIG_IMX_SEC_ENCLAVE`) reject userspace SAB message writes with `EINVAL`;
only in-kernel consumers such as `ele-trng` are available there.

## Support

For questions please email support@wolfssl.com

