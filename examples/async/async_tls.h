/* async-tls.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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


#ifndef WOLFSSL_ASYNC_TLS_EXAMPLES_H
#define WOLFSSL_ASYNC_TLS_EXAMPLES_H

#define DEFAULT_PORT 11111
#define TEST_BUF_SZ  256

/* Force ECC-only certs/keys for these async TLS examples. */
#ifndef ASYNC_ECC_ONLY
#define ASYNC_ECC_ONLY 1
#endif

static WC_INLINE void async_print_ecc_nonblock_status(void)
{
#if defined(WC_ECC_NONBLOCK) && defined(WOLFSSL_HAVE_SP_ECC)
    printf("ECC non-blocking: enabled (WC_ECC_NONBLOCK + WOLFSSL_HAVE_SP_ECC)\n");
#elif defined(WC_ECC_NONBLOCK)
    printf("ECC non-blocking: WC_ECC_NONBLOCK defined but SP-ECC missing\n");
#else
    printf("ECC non-blocking: disabled (WC_ECC_NONBLOCK not defined)\n");
#endif
}

#ifdef WOLF_CRYPTO_CB
/* Example custom context for crypto callback */
typedef struct {
    int pendingCount; /* track pending tries test count */
} AsyncTlsCryptoCbCtx;
int AsyncTlsCryptoCb(int devIdArg, wc_CryptoInfo* info, void* ctx);
#endif /* WOLF_CRYPTO_CB */


int client_async_test(int argc, char** argv);
int server_async_test(int argc, char** argv);


#endif /* WOLFSSL_ASYNC_TLS_EXAMPLES_H */
