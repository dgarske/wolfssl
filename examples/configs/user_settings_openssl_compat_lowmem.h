/* user_settings_openssl_compat_lowmem.h
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

/* OpenSSL compatibility layer sized for small RAM budgets.
 * Keeps the SSL, X509, EVP and BIO compatibility APIs (OPENSSL_EXTRA) and
 * trims the fixed-size buffers the layer adds to each context, session and
 * connection. Each knob below names what it costs in API behavior.
 * The same set of defines is available from autotools with
 * ./configure --enable-opensslextra=lowmem.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_openssl_compat_lowmem.h user_settings.h
 * ./configure --enable-usersettings --disable-examples
 * make
 * ./wolfcrypt/test/testwolfcrypt
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* OpenSSL Compatibility */
/* ------------------------------------------------- */
#define OPENSSL_EXTRA
/* OPENSSL_ALL is left off: it forces session tickets, a per-connection copy
 * of the context certificate and key, and the extra X509_STORE APIs. */

#define WOLFSSL_ERROR_CODE_OPENSSL
#define HAVE_WOLFSSL_SSL_H
#define OPENSSL_COMPATIBLE_DEFAULTS

#ifdef WOLFSSL_NO_SOCK
    #ifndef WOLFSSL_IP4
        #define WOLFSSL_IP4 2
    #endif
    #ifndef WOLFSSL_IP6
        #define WOLFSSL_IP6 10
    #endif
    #ifndef XINET_PTON
        #define XINET_PTON(a,b,c) 0
    #endif
    #ifndef XINET_NTOP
        #define XINET_NTOP(a,b,c,d) NULL
    #endif
#endif

#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/* ------------------------------------------------- */
/* Memory */
/* ------------------------------------------------- */
/* Large temporaries go on the heap instead of the stack. */
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK_CACHE

/* The peer certificate object is allocated when a certificate arrives
 * instead of being embedded in every WOLFSSL. wolfSSL_get_peer_certificate()
 * then returns a reference to it, as OpenSSL does, rather than a copy. */
#define WOLFSSL_DYNAMIC_PEER_CERT

/* Session tickets do not carry the peer certificate, which keeps every
 * ticket-sized buffer about 2 KB smaller. After a TLS 1.3 PSK resumption
 * wolfSSL_get_peer_certificate() returns NULL. */
#define NO_CERT_IN_TICKET

/* Longest external PSK identity and hint. Ticket identities are not
 * limited by this. */
#define MAX_PSK_ID_LEN 128

/* Session tickets up to this size live inside the session; larger ones are
 * allocated. Raise it when the application keeps the default ticket
 * encryption callback and many sessions. */
#define WOLFSSL_STATIC_TICKET_LEN 128

/* Server session cache of 6 entries (default 33). */
#define SMALL_SESSION_CACHE

/* Distinguished names longer than this are truncated by
 * wolfSSL_X509_NAME_oneline(); at most WC_MAX_NAME_ENTRIES attributes are
 * reachable through wolfSSL_X509_NAME_get_entry(). */
#define WC_ASN_NAME_MAX 256
#define WC_MAX_NAME_ENTRIES 8

/* Number of wolfSSL_*_set_ex_data() slots per object. */
#define MAX_EX_DATA 2

/* No certificate_authorities list in CertificateRequest and no
 * wolfSSL_get_client_CA_list(); removes a raw DN copy from every name. */
#define WOLFSSL_NO_CA_NAMES

/* Drops the default ticket encryption key context from every WOLFSSL_CTX;
 * the server must then install a ticket encryption callback
 * (wolfSSL_CTX_set_tlsext_ticket_key_cb or wolfSSL_CTX_set_TicketEncCb). */
#if 0
    #define WOLFSSL_NO_DEF_TICKET_ENC_CB
#endif

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL

/* ------------------------------------------------- */
/* TLS Versions */
/* ------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_HKDF
#define WC_RSA_PSS
#define NO_OLD_TLS

/* TLS Extensions */
#define HAVE_SESSION_TICKET
#define HAVE_SNI
#define HAVE_ALPN
#define HAVE_MAX_FRAGMENT

/* ------------------------------------------------- */
/* Timing Resistance */
/* ------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* ECC */
/* ------------------------------------------------- */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_COMP_KEY

/* ------------------------------------------------- */
/* Curve25519 / Ed25519 */
/* ------------------------------------------------- */
#define HAVE_CURVE25519
#define HAVE_ED25519

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#undef NO_RSA
#define WC_RSA_NO_PADDING
#define WOLFSSL_KEY_GEN

/* ------------------------------------------------- */
/* DH */
/* ------------------------------------------------- */
#undef NO_DH
#define HAVE_FFDHE_2048
#define HAVE_DH_DEFAULT_PARAMS

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AESGCM_STREAM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define HAVE_AES_DECRYPT

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* ------------------------------------------------- */
/* Additional Features */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG
#define HAVE_HKDF
#define HAVE_KEYING_MATERIAL
#define WOLFSSL_HAVE_PRF

/* ------------------------------------------------- */
/* Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_DER_LOAD
#define WOLFSSL_PEM_TO_DER
#define WOLFSSL_DER_TO_PEM
#define WOLFSSL_ALT_NAMES

/* ------------------------------------------------- */
/* Encoding */
/* ------------------------------------------------- */
#define WOLFSSL_BASE16
#define WOLFSSL_BASE64_ENCODE

/* ------------------------------------------------- */
/* PKCS */
/* ------------------------------------------------- */
#define HAVE_PKCS8

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_PSK
#define NO_DES3

/* ------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------- */
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
