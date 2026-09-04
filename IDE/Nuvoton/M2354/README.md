# wolfCrypt on the NuMaker-M2354

Builds `wolfcrypt_test` followed by the wolfCrypt benchmark for the
[NuMaker-M2354](https://www.nuvoton.com/board/numaker-m2354/) (NuMicro
M2354KJFAE, Cortex-M23, 1 MB flash, 256 KB SRAM), with the CRPT accelerator,
the TRNG and the Key Store driven through the crypto callback port in
[wolfcrypt/src/port/nuvoton](../../../wolfcrypt/src/port/nuvoton/README.md).

## What you need

- `arm-none-eabi-gcc` (any recent release; developed against 13.2)
- The Nuvoton BSP:

```sh
git clone --depth 1 https://github.com/OpenNuvoton/M2354BSP
```

The BSP is not vendored into wolfSSL and nothing from it is copied into this
tree; the build reads it where you cloned it.

## Build

```sh
./build.sh --bsp /path/to/M2354BSP
```

That produces `build/wolfcrypt-m2354.elf` and `build/wolfcrypt-m2354.bin` for
the secure world, which is also where a plain non-TrustZone application runs.

For the TrustZone split:

```sh
./build.sh --bsp /path/to/M2354BSP --tz
```

This compiles both halves - the port as the non-secure image sees it, and
`secure/nuvoton_nsc.c` with `-mcmse` - but does not link. A working TrustZone
application also needs a partition layout and a secure bootstrap, and those
belong to your project rather than to wolfSSL. `--tz` does show that the port
and the veneers agree on every signature, which is the part that is easy to get
wrong.

## Flash and run

The board carries a detachable Nu-Link2-Me. Either of these works:

- **NuLink command line** (Nuvoton's tool, Windows and Linux):
  `NuLink -w APROM build/wolfcrypt-m2354.bin`
- **OpenOCD**, using Nuvoton's fork
  ([OpenNuvoton/OpenOCD-Nuvoton](https://github.com/OpenNuvoton/OpenOCD-Nuvoton))
  with `interface/nulink.cfg`. Nuvoton also publishes a `NuLink2_DAPLink.bin`
  adapter firmware that makes the probe a CMSIS-DAP device, after which
  `pyocd flash` works.

Console output goes to UART0 at **115200 8N1**, which the Nu-Link2-Me presents
as a virtual COM port.

## Expected output

```
wolfCrypt on NuMaker-M2354 (96 MHz)
TrustZone: secure world, direct BSP calls
Nuvoton crypto callback device registered as devId 820

--- wolfcrypt_test ---
...
--- benchmark ---
...
```

## Files

| File | What it is |
|---|---|
| `user_settings.h` | wolfCrypt configuration; a starting point for your own |
| `app.c` | Clocks, UART console, the CRPT interrupt handler, and `main()` |
| `secure/nuvoton_nsc.c` | Non-secure callable veneers for a TrustZone build |
| `build.sh` | The build described above |

`app.c` is worth reading for two things a project of your own also needs: the
`CRPT_IRQHandler` that routes the crypto interrupt to `ECC_DriverISR()`,
without which every ECC and RSA call times out, and the `current_time()` and
`LowResTimer()` the benchmark asks for.

## Status

The build is verified; nothing has been run on the board yet. See the Status
section of the port README.

# Support

For questions please email support@wolfssl.com
