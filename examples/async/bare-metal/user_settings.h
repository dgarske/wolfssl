/* Bare-metal user settings for TLS 1.3 client with WOLFSSL_USER_IO. */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFSSL_USER_IO
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_IGNORE_FILE_WARN

#define HAVE_ECC
#define WC_ECC_NONBLOCK
#define ECC_USER_CURVES
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NONBLOCK
#define WOLFSSL_SP_NO_MALLOC
#define ECC_TIMING_RESISTANT

/* NOTE: Some public servers (e.g., google.com) may present RSA certificate
 * chains. For this test, RSA is enabled; a real customer server should be
 * ECC-signed certs only so RSA can be disabled.
 */
#undef NO_RSA /* on by default */
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define WOLFSSL_HAVE_SP_RSA

#define HAVE_AESGCM

#define WOLFSSL_TLS13
#define HAVE_HKDF
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SNI

#define HAVE_SESSION_TICKET

extern int posix_getdevrandom(unsigned char *out, unsigned int sz);
#ifndef HAVE_HASHDRBG
    #define CUSTOM_RAND_GENERATE_BLOCK posix_getdevrandom
#else
    #define CUSTOM_RAND_GENERATE_SEED  posix_getdevrandom
#endif

/* Minimal feature set - explicitly disable unwanted algorithms. */
#define NO_DH
#define NO_DSA
#define WOLFSSL_NO_SHAKE256
#define WOLFSSL_NO_SHAKE128
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_SHA
#define NO_OLD_TLS

/* Debugging helper. */
#define DEBUG_WOLFSSL
/* #define WOLFSSL_DEBUG_NONBLOCK */

#endif /* WOLFSSL_USER_SETTINGS_H */
