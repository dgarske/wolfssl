#ifndef _USER_SETTINGS_H_
#define _USER_SETTINGS_H_


/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define FREERTOS
#define FREESCALE_KSDK_FREERTOS
#define FREESCALE_KSDK_2_0_RNGA
#define FREESCALE_COMMON
#define FSL_HW_CRYPTO_MANUAL_SELECTION
#define FREESCALE_USE_MMCAU
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_USER_IO
#define XTIME(tl) time((tl))


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_TLS13
//#define WOLFSSL_KEY_GEN
//#define WOLFSSL_OLD_PRIME_CHECK
//#define KEEP_PEER_CERT
//#define HAVE_COMP_KEY
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define WOLFSSL_BASE64_ENCODE

/* TLS Session Cache */
#define SMALL_SESSION_CACHE
//#define NO_SESSION_CACHE


/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
#define SIZEOF_LONG_LONG 8
#if 1
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT

    /* Optimizations */
    //#define TFM_ARM
#endif

/* Wolf Single Precision Math */
#if 1
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #define WOLFSSL_HAVE_SP_RSA
    //#define WOLFSSL_HAVE_SP_DH
    #define WOLFSSL_HAVE_SP_ECC
    //#define WOLFSSL_SP_CACHE_RESISTANT
    #define WOLFSSL_SP_MATH     /* only SP math - eliminates fast math code */

    /* SP Assembly Speedups */
    #define WOLFSSL_SP_ASM      /* required if using the ASM versions */
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM
#endif


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#if 1
    #ifdef USE_FAST_MATH
        /* Maximum math bits (Max RSA key bits * 2) */
        #define FP_MAX_BITS     4096
    #endif

    /* half as much memory but twice as slow */
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
	#define WC_RSA_BLINDING

    /* RSA PSS Support */
    #ifdef WOLFSSL_TLS13
        #define WC_RSA_PSS
    #endif
#else
    #define NO_RSA
#endif

/* ECC */
#undef HAVE_ECC
#if 1
    #define HAVE_ECC

    /* Manually define enabled curves */
    #define ECC_USER_CURVES
    #ifdef ECC_USER_CURVES
        /* Manual Curve Selection */
        //#define HAVE_ECC192
        //#define HAVE_ECC224
        #undef NO_ECC256
        //#define HAVE_ECC384
        //#define HAVE_ECC521
    #endif

    /* Fixed point cache (speeds repeated operations against same private key) */
    //#define FP_ECC
    #ifdef FP_ECC
        /* Bits / Entries */
        #undef  FP_ENTRIES
        #define FP_ENTRIES  2
        #undef  FP_LUT
        #define FP_LUT      4
    #endif

    /* Optional ECC calculation method */
    /* Note: doubles heap usage, but slightly faster */
    #define ECC_SHAMIR

    /* Reduces heap usage, but slower */
    #define ECC_TIMING_RESISTANT

    /* Compressed Key Support */
    #define HAVE_COMP_KEY

    /* Use alternate ECC size for ECC math */
    #ifdef USE_FAST_MATH
        /* MAX ECC BITS = ROUND8(MAX ECC) * 2 */
        #ifdef NO_RSA
            /* Custom fastmath size if not using RSA */
            #define FP_MAX_BITS     (256 * 2)
        #else
            #define ALT_ECC_SIZE
        #endif
    #endif
#endif

/* DH */
#if 0
    /* Use table for DH instead of -lm (math) lib dependency */
    #if 0
        #define WOLFSSL_DH_CONST
        #define HAVE_FFDHE_2048
        //#define HAVE_FFDHE_4096
        //#define HAVE_FFDHE_6144
        //#define HAVE_FFDHE_8192
    #endif
#else
    #define NO_DH
#endif


/* AES */
#if 1
	#define HAVE_AES_CBC
    #define HAVE_AESGCM
    #define GCM_SMALL /* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    //#define WOLFSSL_AES_DIRECT
    //#define HAVE_AES_ECB
    //#define WOLFSSL_AES_COUNTER
    //#define HAVE_AESCCM
#else
    #define NO_AES
#endif


/* DES3 */
#if 0
#else
    #define NO_DES3
#endif

/* ChaCha20 / Poly1305 */
#if 0
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for TLS */
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#if 0
    #define HAVE_CURVE25519
    #define HAVE_ED25519 /* ED25519 Requires SHA512 */

    /* Optionally use small math (less flash usage, but much slower) */
    #if 1
        #define CURVED25519_SMALL
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#if 1
    /* 1k smaller, but 25% slower */
    //#define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#if 1
    /* not unrolled - ~2k smaller and ~25% slower */
    //#define USE_SLOW_SHA256

    /* Sha224 */
    #if 0
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

/* Sha512 */
#if 0
    #define WOLFSSL_SHA512

    /* Sha384 */
    #if 0
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA512
#endif

/* Sha3 */
#if 0
    #define WOLFSSL_SHA3
#endif

/* MD5 */
#if 0

#else
    #define NO_MD5
#endif

/* HKDF */
#if 1
    #define HAVE_HKDF
#endif

/* CMAC */
#if 0
    #define WOLFSSL_CMAC
#endif


/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
/* Use reduced benchmark / test sizes */
#define BENCH_EMBEDDED

#define USE_CERT_BUFFERS_2048
//#define USE_CERT_BUFFERS_1024
#define USE_CERT_BUFFERS_256


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if 0
    #define DEBUG_WOLFSSL
#else
    #if 0
        #define NO_ERROR_STRINGS
    #endif
#endif



/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
//#define NO_WOLFSSL_SERVER
#define NO_WOLFSSL_CLIENT
//#define NO_CRYPT_TEST
//#define NO_CRYPT_BENCHMARK
//#define WOLFCRYPT_ONLY

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
//#define NO_INLINE

#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_DSA
#define NO_RC4
#define NO_OLD_TLS
#define NO_HC128
#define NO_RABBIT
#define NO_PSK
#define NO_MD4
#define NO_PWDBASED
//#define NO_CODING
//#define NO_ASN_TIME
//#define NO_CERTS
//#define NO_SIG_WRAPPER


#endif /* _USER_SETTINGS_H_ */
