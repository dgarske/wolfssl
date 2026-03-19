/* puf_linker_example.ld
 *
 * Example linker script snippet for SRAM PUF on STM32.
 *
 * Place this section at a fixed SRAM address that is NOT initialized by the
 * startup code.  The PUF reads the power-on SRAM state before any
 * zero-initialization occurs.
 *
 * Usage: Include or merge this into your project's main linker script.
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 */

MEMORY
{
    /* Adjust origins and lengths for your specific STM32 variant */
    FLASH  (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
    RAM    (rwx) : ORIGIN = 0x20000000, LENGTH = 112K
    /* Reserve last 4K of SRAM for PUF (not touched by startup .bss clear) */
    PUF_RAM (rw) : ORIGIN = 0x2001C000, LENGTH = 4K
}

SECTIONS
{
    /* ... other sections ... */

    /* PUF SRAM section: NOLOAD prevents startup code from zeroing this region.
     * The raw power-on state of these bytes is the PUF source. */
    .puf_sram (NOLOAD) :
    {
        . = ALIGN(4);
        _puf_sram_start = .;
        KEEP(*(.puf_sram))
        KEEP(*(.puf_sram.*))
        _puf_sram_end = .;
    } > PUF_RAM

    /* ... other sections ... */
}

/*
 * In your application code, declare the PUF SRAM buffer:
 *
 *   __attribute__((section(".puf_sram")))
 *   static volatile uint8_t puf_sram_region[256];
 *
 * Then pass it to wc_PufReadSram():
 *
 *   wc_PufReadSram(&ctx, (const byte*)puf_sram_region, sizeof(puf_sram_region));
 *
 * IMPORTANT: Do NOT access puf_sram_region before calling wc_PufReadSram().
 * Any read/write to this region before the PUF measurement will corrupt the
 * power-on randomness.
 */
