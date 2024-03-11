/* TLS v1.2 client only, ECC only
 */

/* Derived using:
 * ./configure --disable-rsa --disable-dh --disable-tls13 --disable-chacha --disable-poly1305 --disable-sha224 --disable-sha --disable-md5
 * And generated wolfssl/options.h
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_USER_IO /* Use the SetIO callbacks, not the internal wolfio.c socket code */
#define WOLFSSL_IGNORE_FILE_WARN /* ignore file includes not required */
//#define WOLFSSL_SMALL_STACK /* option to reduce stack size, offload to heap */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_SIG_WRAPPER
#define SINGLE_THREADED

/* ------------------------------------------------------------------------- */
/* CryptoCell */
/* ------------------------------------------------------------------------- */
#if 1
    #define WOLFSSL_CRYPTOCELL_312

    /* Disable DRBG and use CC312 TRNG directly */
    extern int cc310_random_generate(unsigned char* output, unsigned int size);
    #define CUSTOM_RAND_GENERATE_BLOCK  cc310_random_generate
    #define WC_NO_HASHDRBG

    //#define WOLFSSL_CRYPTOCELL
    //#define WOLFSSL_CRYPTOCELL_AES

    //#define WOLFSSL_HAVE_PSA
    //#define WOLFSSL_PSA_GLOBAL_LOCK
#endif

/* ------------------------------------------------------------------------- */
/* Math */
/* ------------------------------------------------------------------------- */
/* Math Options */
#if 1 /* Single-precision (SP) wolf math - ECC only */
    #define WOLFSSL_HAVE_SP_ECC   /* use sp_c32.c for math */
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #define WOLFSSL_SP_MATH       /* only SP math - eliminates fast math code */
    #define SP_DIV_WORD_USE_DIV
    #if 0
        /* optional 10x speedup with inline assembly adds about 200 bytes to flash */
        #define WOLFSSL_SP_ARM_CORTEX_M_ASM
        #define WOLFSSL_SP_USE_UDIV
    #endif

#elif 1
    /* Multi-precision wolf math */
    #define WOLFSSL_SP_MATH_ALL   /* use sp_int.c generic math */
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
#else
    /* Fast Math - tfm.c */
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
    #define WOLFSSL_NO_ASM
#endif


/* ------------------------------------------------------------------------- */
/* TLS */
/* ------------------------------------------------------------------------- */
/* Enable TLS v1.2 (on by default) */
#undef  WOLFSSL_NO_TLS12
/* Disable TLS server code */
#define NO_WOLFSSL_SERVER
/* Disable TLS v1.3 code */
#undef  WOLFSSL_TLS13
/* Disable older TLS version prior to 1.2 */
#define NO_OLD_TLS

/* Enable default TLS extensions */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
//#define HAVE_ENCRYPT_THEN_MAC
//#define HAVE_SERVER_RENEGOTIATION_INFO
//#define HAVE_SNI /* optional Server Name Indicator (SNI) */

/* ASN */
#define WOLFSSL_ASN_TEMPLATE /* use newer ASN template asn.c code (default) */
#define WOLFSSL_NO_ASN_STRICT
#define IGNORE_NAME_CONSTRAINTS

/* Disable Features */
#define NO_SESSION_CACHE /* disable session resumption */
#define NO_PSK /* pre-shared-key support */


/* ------------------------------------------------------------------------- */
/* Algorithms */
/* ------------------------------------------------------------------------- */
/* RNG */
#ifndef WC_NO_HASHDRBG
    #define HAVE_HASHDRBG /* Use DRBG SHA2-256 and seed */
#endif

/* Enable ECC */
#define HAVE_ECC
#define ECC_USER_CURVES      /* Enable only ECC curves specific */
#undef  NO_ECC256            /* Enable SECP256R1 only (on by default) */
#define ECC_TIMING_RESISTANT /* Enable Timing Resistance */
//#define ECC_SHAMIR         /* Optional ECC calculation speed improvement if not using SP implementation */

/* RSA: Optional */
#if 0
    #undef NO_RSA
    #define WC_RSA_BLINDING
#else
    #define NO_RSA
#endif

/* Math fixups */
#ifdef WOLFSSL_SP_MATH
    /* If SP math only then make sure SP RSA is enabled */
    #ifndef NO_RSA
        #define WOLFSSL_HAVE_SP_RSA
    #endif
#endif
#ifdef WOLFSSL_SP_MATH_ALL
    #ifndef NO_RSA
        #define SP_INT_BITS 2048
    #elif defined(HAVE_ECC)
        #define SP_INT_BITS 256
    #endif
#endif
#ifdef USE_FAST_MATH
    /* If using fast math (tfm.c) adjust the default math bits (2 * max) */
    #ifndef NO_RSA
        #define FP_MAX_BITS (2*2048)
    #elif defined(HAVE_ECC)
        #define FP_MAX_BITS (2*256)
    #endif
#endif
#if defined(USE_FAST_MATH) && defined(HAVE_ECC) && !defined(NO_RSA)
    #define ALT_ECC_SIZE /* use heap allocation for ECC point */
#endif

/* Enable SHA2-256 (on by default) */
#undef NO_SHA256
#define USE_SLOW_SHA256

/* Enable AES GCM */
#define HAVE_AESGCM
#define GCM_SMALL /* use small GHASH table */
#define NO_AES_CBC /* Disable AES CBC */
#define NO_AES_192
#define NO_AES_256
#define WOLFSSL_AES_SMALL_TABLES
#define WC_NO_CACHE_RESISTANT

/* BTLE needs CMAC */
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC

/* Optional Features */
//#define WOLFSSL_BASE64_ENCODE /* Enable Base64 encoding */


/* Disable Algorithms */
#define NO_DH
#define NO_SHA
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PWDBASED
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS
#if 0
    #define DEBUG_WOLFSSL
#else
    #if 1
        #define NO_ERROR_STRINGS
    #endif
#endif

#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_USER_SETTINGS_H */
