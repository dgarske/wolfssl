#!/bin/bash
#
# Build the wolfCrypt test and benchmark application for the NuMaker-M2354.
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# Usage:
#   ./build.sh --bsp /path/to/M2354BSP          secure world image (default)
#   ./build.sh --bsp /path/to/M2354BSP --tz     TrustZone compile check
#
# Get the BSP with:
#   git clone --depth 1 https://github.com/OpenNuvoton/M2354BSP
#
# The secure build links a complete .elf you can flash. The --tz build is a
# compile check of both halves of the TrustZone split: the port sources as the
# non-secure image sees them, and the secure veneers with -mcmse. It does not
# link, because a working TrustZone application also needs a partition layout
# and a secure bootstrap that belong to your project rather than to wolfSSL.

set -e

CC=${CC:-arm-none-eabi-gcc}
OBJCOPY=${OBJCOPY:-arm-none-eabi-objcopy}
SIZE=${SIZE:-arm-none-eabi-size}

BSP=""
TZ=0
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="$HERE/build"

while [ $# -gt 0 ]; do
    case "$1" in
        --bsp) BSP="$2"; shift 2 ;;
        --tz)  TZ=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$BSP" ]; then
    echo "give the BSP location with --bsp /path/to/M2354BSP" >&2
    exit 1
fi

DEV="$BSP/Library/Device/Nuvoton/M2354"
STD="$BSP/Library/StdDriver"

for d in "$DEV/Include" "$STD/inc" "$BSP/Library/CMSIS/Include"; do
    if [ ! -d "$d" ]; then
        echo "not a M2354BSP checkout: $d is missing" >&2
        exit 1
    fi
done

rm -rf "$OUT"
mkdir -p "$OUT"

INC="-I$ROOT -I$HERE -I$DEV/Include -I$STD/inc -I$BSP/Library/CMSIS/Include"

CFLAGS="-mcpu=cortex-m23 -mthumb -Os -ffunction-sections -fdata-sections"
CFLAGS="$CFLAGS -Wall -Wextra -Werror -DWOLFSSL_USER_SETTINGS $INC"

# wolfCrypt, minus the two files that are #included into others rather than
# compiled on their own.
WC_SRC=""
for f in "$ROOT"/wolfcrypt/src/*.c; do
    case "$(basename "$f")" in
        misc.c|evp.c) continue ;;
    esac
    WC_SRC="$WC_SRC $f"
done
WC_SRC="$WC_SRC $ROOT/wolfcrypt/test/test.c $ROOT/wolfcrypt/benchmark/benchmark.c"

PORT_SRC="$ROOT/wolfcrypt/src/port/nuvoton/nuvoton_hw.c
          $ROOT/wolfcrypt/src/port/nuvoton/nuvoton_cryptocb.c
          $ROOT/wolfcrypt/src/port/nuvoton/nuvoton_cb_rng.c
          $ROOT/wolfcrypt/src/port/nuvoton/nuvoton_cb_hash.c
          $ROOT/wolfcrypt/src/port/nuvoton/nuvoton_cb_cipher.c
          $ROOT/wolfcrypt/src/port/nuvoton/nuvoton_cb_pk.c
          $ROOT/wolfcrypt/src/port/nuvoton/nuvoton_key.c"

BSP_SRC="$DEV/Source/system_M2354.c
         $STD/src/clk.c
         $STD/src/sys.c
         $STD/src/uart.c
         $STD/src/crypto.c
         $STD/src/keystore.c
         $STD/src/rng.c
         $STD/src/fmc.c"

# The BSP is vendor code and does not build clean under our warning set (its
# RSA driver compares a pointer against NULL as an integer), so it gets the
# same flags without -Werror.
BSPFLAGS="-mcpu=cortex-m23 -mthumb -Os -ffunction-sections -fdata-sections"
BSPFLAGS="$BSPFLAGS -DWOLFSSL_USER_SETTINGS $INC"

compile() {
    # compile <output dir> <compiler flags> <sources...>
    local dir="$1"; shift
    local flags="$1"; shift
    local src obj

    mkdir -p "$dir"
    for src in "$@"; do
        obj="$dir/$(echo "$src" | md5sum | cut -c1-12)_$(basename "$src" | sed 's/\.[cS]$//').o"
        # shellcheck disable=SC2086
        $CC $flags -c "$src" -o "$obj" || exit 1
        echo "$obj"
    done
}

if [ "$TZ" -eq 0 ]; then
    echo "=== secure world build ==="

    # shellcheck disable=SC2086
    OBJS=$(compile "$OUT/obj" "$CFLAGS -DWOLFSSL_NUVOTON_SECURE" \
        $WC_SRC $PORT_SRC "$HERE/app.c") || exit 1
    # shellcheck disable=SC2086
    OBJS="$OBJS $(compile "$OUT/obj" "$BSPFLAGS" $BSP_SRC)" || exit 1

    # The BSP startup is assembly and the retarget file wants the BSP's own
    # warning level, so neither goes through -Werror.
    $CC -mcpu=cortex-m23 -mthumb $INC -c "$DEV/Source/GCC/startup_M2354.S" \
        -o "$OUT/obj/startup.o"
    $CC -mcpu=cortex-m23 -mthumb -Os $INC -c "$DEV/Source/GCC/_syscalls.c" \
        -o "$OUT/obj/syscalls.o"

    # shellcheck disable=SC2086
    $CC -mcpu=cortex-m23 -mthumb -T"$DEV/Source/GCC/gcc_arm.ld" \
        -Wl,--gc-sections -Wl,-Map="$OUT/wolfcrypt-m2354.map" \
        --specs=nano.specs --specs=nosys.specs \
        $OBJS "$OUT/obj/startup.o" "$OUT/obj/syscalls.o" \
        -o "$OUT/wolfcrypt-m2354.elf" -lm

    $OBJCOPY -O binary "$OUT/wolfcrypt-m2354.elf" "$OUT/wolfcrypt-m2354.bin"
    $SIZE "$OUT/wolfcrypt-m2354.elf"

    echo
    echo "built $OUT/wolfcrypt-m2354.elf"
    echo "flash with: nuvoton NuLink or OpenOCD, see README.md"
else
    echo "=== TrustZone compile check ==="

    # A TrustZone project must put its own partition_M2354.h ahead of the
    # BSP's, which errors out if it is the one that gets picked up. wolfSSL
    # does not ship a copy of that Nuvoton file, so take the BSP's and drop
    # the guard; a real project edits it for its own memory split.
    mkdir -p "$OUT/tz"
    sed '/# error "Link to default partition_M2354.h in secure mode/d' \
        "$STD/inc/partition_M2354.h" > "$OUT/tz/partition_M2354.h"

    echo "--- non-secure: the port as wolfCrypt sees it"
    # shellcheck disable=SC2086
    compile "$OUT/obj-ns" "$CFLAGS -DWOLFSSL_NUVOTON_NSC" $PORT_SRC >/dev/null

    # The local partition header has to come first on the include path, ahead
    # of the BSP's, or the BSP's is the one that gets picked up.
    TZFLAGS="-I$OUT/tz -mcmse"
    TZFLAGS="$TZFLAGS -DWOLFSSL_NUVOTON_SECURE -DWOLFSSL_NUVOTON_NSC_IMPL"

    echo "--- secure: the NSC veneers"
    # shellcheck disable=SC2086
    $CC $TZFLAGS $CFLAGS \
        -c "$HERE/secure/nuvoton_nsc.c" -o "$OUT/obj-ns/nuvoton_nsc.o"

    echo "--- secure: the hardware layer the veneers call"
    # shellcheck disable=SC2086
    $CC $TZFLAGS $CFLAGS \
        -c "$ROOT/wolfcrypt/src/port/nuvoton/nuvoton_hw.c" \
        -o "$OUT/obj-ns/nuvoton_hw_s.o"

    echo
    echo "both halves compile"
fi
