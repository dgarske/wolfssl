/* ele_rng.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* True random number generator of the NXP EdgeLock Secure Enclave.
 *
 * On i.MX93 / i.MX95 the in-kernel fsl-se driver registers the enclave TRNG
 * with the Linux hwrng framework, so the entropy is reached through an
 * ordinary character device rather than the enclave message interface. That
 * means this file needs no NXP userspace library. Confirm the backing source
 * on the target with:
 *     cat /sys/class/misc/hw_random/rng_current      -> ele-trng
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_NXP_ELE

#include <wolfssl/wolfcrypt/port/nxp/ele.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_NXP_ELE_TRNG

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* Cached descriptor for the hwrng node. Opening it per call is measurable
 * when seeding repeatedly, and the node has no per-open state. */
static int eleTrngFd = -1;

static int wc_ele_trng_open(void)
{
    if (eleTrngFd >= 0) {
        return 0;
    }

    eleTrngFd = open(WOLFSSL_NXP_ELE_TRNG_DEVICE, O_RDONLY);
    if (eleTrngFd < 0) {
        /* EACCES is the common case: the hwrng node is root-only by
         * default. Say so rather than leaving a bare error code. */
        if (errno == EACCES) {
            WOLFSSL_MSG("ELE TRNG: permission denied opening hwrng device; "
                        "the node is root-only unless a udev rule grants "
                        "access");
        }
        else {
            WOLFSSL_MSG("ELE TRNG: unable to open hwrng device");
        }
        return WC_HW_E;
    }

    return 0;
}

void wc_ele_trng_cleanup(void)
{
    if (eleTrngFd >= 0) {
        close(eleTrngFd);
        eleTrngFd = -1;
    }
}

int wc_ele_trng_read(byte* buf, word32 sz)
{
    int ret;
    ssize_t got;
    word32 pos = 0;

    if (buf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }

    ret = wc_ele_trng_open();
    if (ret != 0) {
        return ret;
    }

    /* The hwrng framework may return short reads when the enclave's entropy
     * pool needs to refill, so loop until satisfied. */
    while (pos < sz) {
        got = read(eleTrngFd, buf + pos, (size_t)(sz - pos));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            WOLFSSL_MSG("ELE TRNG: read failed");
            wc_ele_trng_cleanup();
            return RNG_FAILURE_E;
        }
        if (got == 0) {
            /* No progress available; treat as a hardware failure rather than
             * spinning, so the caller can fall back. */
            WOLFSSL_MSG("ELE TRNG: no entropy returned");
            wc_ele_trng_cleanup();
            return RNG_FAILURE_E;
        }
        pos += (word32)got;
    }

    return 0;
}

#endif /* WOLFSSL_NXP_ELE_TRNG */
#endif /* WOLFSSL_NXP_ELE */
