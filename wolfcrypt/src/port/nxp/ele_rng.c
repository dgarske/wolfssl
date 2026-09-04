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

/* The descriptor is opened per read rather than cached: wolfCrypt seeds from
 * multiple threads, and a cached file-scope fd would need locking around
 * open, read and cleanup to avoid a double-open leak or a close under a
 * concurrent reader. Seeding is rare (DRBG instantiate/reseed), so the
 * per-call open cost does not matter. wc_open_cloexec keeps the descriptor
 * from leaking across fork/exec, matching the entropy-device opens in
 * wolfcrypt/src/random.c. */
static int wc_ele_trng_open(void)
{
    int fd = wc_open_cloexec(WOLFSSL_NXP_ELE_TRNG_DEVICE, O_RDONLY);
    if (fd < 0) {
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

    return fd;
}

int wc_ele_trng_read(byte* buf, word32 sz)
{
    int fd;
    ssize_t got;
    word32 pos = 0;

    if (buf == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }

    fd = wc_ele_trng_open();
    if (fd < 0) {
        return fd;
    }

    /* The hwrng framework may return short reads when the enclave's entropy
     * pool needs to refill, so loop until satisfied. */
    while (pos < sz) {
        got = read(fd, buf + pos, (size_t)(sz - pos));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            WOLFSSL_MSG("ELE TRNG: read failed");
            close(fd);
            return RNG_FAILURE_E;
        }
        if (got == 0) {
            /* No progress available; treat as a hardware failure rather than
             * spinning, so the caller can fall back. */
            WOLFSSL_MSG("ELE TRNG: no entropy returned");
            close(fd);
            return RNG_FAILURE_E;
        }
        pos += (word32)got;
    }

    close(fd);
    return 0;
}

#endif /* WOLFSSL_NXP_ELE_TRNG */
#endif /* WOLFSSL_NXP_ELE */
