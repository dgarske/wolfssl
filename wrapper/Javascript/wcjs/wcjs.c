#include "wcjs.h"


static WC_RNG rng;


#ifdef CONFIG_DEBUG
static int ALLOCS = 0;
void hexdump(FILE * stream, void const * data, unsigned int len)
{
    unsigned int i;
    unsigned int r,c;

    if (!stream)
        return;
    if (!data)
        return;

    for (r=0,i=0; r<(len/16+(len%16!=0)); r++,i+=16) {
        fprintf(stream,"%04X:   ",i); /* location of first byte in line */

        for (c=i; c<i+8; c++) { /* left half of hex dump */
            if (c<len)
                fprintf(stream,"%02X ",((unsigned char const *)data)[c]);
            else
                fprintf(stream,"   "); /* pad if short line */
        }
        fprintf(stream,"  ");

        for (c=i+8; c<i+16; c++) { /* right half of hex dump */
            if (c<len)
                fprintf(stream,"%02X ",((unsigned char const *)data)[c]);
            else
                fprintf(stream,"   "); /* pad if short line */
        }

        fprintf(stream,"   ");

        for (c=i; c<i+16; c++) { /* ASCII dump */
            if (c<len) {
                if (((unsigned char const *)data)[c]>=32 &&
                    ((unsigned char const *)data)[c]<127)
                    fprintf(stream,"%c",((char const *)data)[c]);
                else
                    fprintf(stream,"."); /* put this for non-printables */
            }
            else
                fprintf(stream," "); /* pad if short line */
        }
        fprintf(stream,"\n");
    }

    fflush(stream);
}
#endif

/////////////////////////////////////////////////////////////////////////
// wcjs_alloc
void* wcjs_alloc(size_t sz)
{
#ifdef CONFIG_DEBUG
    ALLOCS++;
#endif
    return malloc(sz);
}

/////////////////////////////////////////////////////////////////////////
// wcjs_free
void wcjs_free(void* ptr)
{
#ifdef CONFIG_DEBUG
    ALLOCS--;
#endif
    free(ptr);
}



/////////////////////////////////////////////////////////////////////////
// pkcs7_unpad()
size_t pkcs7_unpad(uint8_t* in, size_t len)
{
    FATAL(len<BLOCK_SIZE);
    size_t ret = len - in[len-1];

    return ret;
}



/////////////////////////////////////////////////////////////////////////
// hmac
uint8_t* hmac(uint8_t* input, size_t inputLen,
    uint8_t* key, size_t keyLen, size_t* digestLen)
{
    int          sc;
    Hmac         hmac;
    uint8_t*     digest;

    digest = wcjs_alloc(SHA256_DIGEST_SIZE);
    FATAL(!digest);

    sc = wc_HmacSetKey(&hmac, SHA256, (byte*)key, keyLen);
    FATAL (sc != 0);

    sc = wc_HmacUpdate(&hmac, (byte*)input, (word32)inputLen);
    FATAL (sc != 0);

    sc = wc_HmacFinal(&hmac, digest);
    FATAL (sc != 0)

    *digestLen = 32;

    return digest;
}




/////////////////////////////////////////////////////////////////////////
// sha256
uint8_t* sha256(uint8_t* buf, size_t bufLen)
{
    int sc;
    Sha256 sha256;
    uint8_t* digest = NULL;

    digest = wcjs_alloc(SHA256_DIGEST_SIZE);
    FATAL(NULL==digest);

    sc = wc_InitSha256(&sha256);
    FATAL(sc != 0);

    sc = wc_Sha256Update(&sha256, buf, bufLen);
    FATAL(sc != 0);

    sc = wc_Sha256Final(&sha256, digest);
    FATAL(sc != 0);

    wc_Sha256Free(&sha256);

    return digest;
}



/////////////////////////////////////////////////////////////////////////
// randomBytes()
int randomBytes(void* bytes, int len)
{
    int sc;

    sc = wc_RNG_GenerateBlock(&rng, bytes, len);
    FATAL(sc != 0);

    return 1;
}


/////////////////////////////////////////////////////////////////////////
// randomBytesAlloc
uint8_t* randomBytesAlloc(int len)
{
    uint8_t* ret;

    ret = wcjs_alloc(len);
    FATAL(NULL==ret);

    randomBytes(ret, len);
    return ret;
}

/////////////////////////////////////////////////////////////////////////
// randInt()
uint32_t randInt(unsigned int max)
{
    unsigned int ret;

    randomBytes(&ret, sizeof(ret));
    return (ret % max);
}



/////////////////////////////////////////////////////////////////////////
// generateInitializationVector()
uint8_t* generateInitializationVector(size_t length)
{
   return randomBytesAlloc(length);
}



/////////////////////////////////////////////////////////////////////////
// cryptor()
uint8_t* cryptor(uint8_t* input, size_t inputLen, uint8_t* key, uint8_t* iv,
    size_t* outputLen, int enc, int cipherMode, uint8_t tag[TAG_SIZE])
{
    int      sc;
    uint8_t* output  = NULL;
    Aes      aes;

    FATAL(!input);
    FATAL(!iv);
    FATAL(!key);

    sc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    FATAL(sc != 0);

    output = wcjs_alloc(inputLen + 256);
    FATAL(!output);

    switch (cipherMode)
    {
        //////////////////////
        case MODE_AES_256_GCM:
        {
            const byte auth[] =
            {
                0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                0xab, 0xad, 0xda, 0xd2
            };

            sc = wc_AesGcmSetKey(&aes, key, AES_KEY_SIZE);
            FATAL(sc!=0);
            if (enc) {
                sc = wc_AesGcmEncrypt(&aes,
                    output,
                    input, inputLen,
                    iv,  AES_IV_SIZE,
                    tag, TAG_SIZE,
                    auth, sizeof(auth)
                );
                *outputLen = inputLen;
                FATAL(sc!=0);
            } else {
                sc = wc_AesGcmEncrypt(&aes,
                    output,
                    input, inputLen,
                    iv,  AES_IV_SIZE,
                    tag, TAG_SIZE,
                    auth, sizeof(auth)
                );
                *outputLen = inputLen;
                FATAL(sc!=0);
            }
            break;

        }

        //////////////////////
        case MODE_AES_256_CBC:
        {
            FATAL((inputLen % BLOCK_SIZE)!=0);
            FATAL(inputLen < BLOCK_SIZE);

            if (enc) {
                sc = wc_AesSetKey(&aes, key, AES_KEY_SIZE, NULL, AES_ENCRYPTION);
                FATAL(sc!=0);

                sc = wc_AesCbcEncrypt(&aes, output, input, inputLen);
                *outputLen = inputLen;
                FATAL(sc!=0);
            } else {
                sc = wc_AesSetKey(&aes, key, AES_KEY_SIZE, NULL, AES_DECRYPTION);
                FATAL(sc!=0);

                sc = wc_AesCbcDecrypt(&aes, output, input, inputLen);
                *outputLen = inputLen;
                FATAL(sc!=0);
            }
            break;
        }
        default:
        {
            FATAL(1);
        }
    }

    wc_AesFree(&aes);

finally:

    return output;
}

/////////////////////////////////////////////////////////////////////////
// encryptor()
uint8_t* encryptor(uint8_t* input, size_t inputLen, uint8_t* key,
    uint8_t* iv, size_t* outputLen, int cipherMode, uint8_t tag[TAG_SIZE])
{
    return cryptor(input, inputLen, key, iv, outputLen, 1, cipherMode, tag);
}


/////////////////////////////////////////////////////////////////////////
// decryptor()
uint8_t* decryptor(uint8_t* input, size_t inputLen, uint8_t* key, uint8_t* iv,
    size_t* outputLen, int cipherMode, uint8_t tag[TAG_SIZE])
{
    return cryptor(input, inputLen, key, iv, outputLen, 0, cipherMode, tag);
}


#ifndef NO_RSA

/////////////////////////////////////////////////////////////////////////
// decryptWithPrivateKeyRsa()
uint8_t* decryptWithPrivateKeyRsa(RsaKey* rsa, uint8_t* cipher, int cipherLen,
    int* plainLen)
{
    int         sc;
    uint8_t*    plain;

    plain = wcjs_alloc(cipherLen * 2);
    FATAL(!plain);

    *plainLen = wc_RsaPrivateDecrypt(cipher, cipherLen, plain, cipherLen * 2,
        rsa);
    FATAL(*plainLen < 1);

    return plain;
}




/////////////////////////////////////////////////////////////////////////
// encryptWithPublicKeyRsa()
uint8_t* encryptWithPublicKeyRsa(RsaKey* rsa, uint8_t* plain, int plainLen,
    int* cipherLen)
{
    int         sc;
    uint8_t*    cipher;

    *cipherLen = wc_RsaEncryptSize(rsa);
    FATAL(*cipherLen<1);

    cipher = wcjs_alloc((*cipherLen) * 2);
    FATAL(!cipher);

    *cipherLen = wc_RsaPublicEncrypt(plain, plainLen, cipher, *cipherLen,
        rsa, &rng);
    FATAL(*cipherLen<1);

    return cipher;
}

int rsaLoadKeyPem(RsaKey* rsa, uint8_t* keyPem, int type)
{
    int         sc;
    int         keyPemLen, keyDerLen;
    uint8_t*    keyDer;
    word32      inOutIdx = 0;

    keyPemLen = XSTRLEN((char*)keyPem);

    keyDer = wcjs_alloc(keyPemLen);
    FATAL(!keyDer);

    if (type == PRIVATEKEY_TYPE) {
        sc = wolfSSL_KeyPemToDer(keyPem, keyPemLen, keyDer, keyPemLen, NULL);
        FATAL(sc < 0);
        keyDerLen = sc;

        sc = wc_RsaPrivateKeyDecode(keyDer, &inOutIdx, rsa, keyDerLen);
    }
    else {
        sc = wolfSSL_PubKeyPemToDer(keyPem, keyPemLen, keyDer, keyPemLen);
        FATAL(sc < 0);
        keyDerLen = sc;

        sc = wc_RsaPublicKeyDecode(keyDer, &inOutIdx, rsa, keyDerLen);
    }

    wcjs_free(keyDer);

    return sc;
}

/////////////////////////////////////////////////////////////////////////
// decryptWithPrivateKey()
uint8_t* decryptWithPrivateKey(uint8_t* keyPem, uint8_t* cipher, int cipherLen,
    int* plainLen)
{
    RsaKey      rsa;
    int         sc;
    uint8_t*    plain;

    sc = rsaLoadKeyPem(&rsa, keyPem, PRIVATEKEY_TYPE);
    FATAL(sc != 0);

    plain = decryptWithPrivateKeyRsa(&rsa, cipher, cipherLen, plainLen);
    FATAL(!plain);

    wc_FreeRsaKey(&rsa);

    return plain;
}



/////////////////////////////////////////////////////////////////////////
// encryptWithPublicKey
uint8_t* encryptWithPublicKey(uint8_t* keyPem, uint8_t* plain, int plainLen,
    int* cipherLen)
{
    RsaKey      rsa;
    int         sc;
    uint8_t*    cipher;

    *cipherLen = plainLen;

    sc = rsaLoadKeyPem(&rsa, keyPem, PUBLICKEY_TYPE);
    FATAL(sc != 0);

    cipher = encryptWithPublicKeyRsa(&rsa, plain, plainLen, cipherLen);
    FATAL(!cipher);

    wc_FreeRsaKey(&rsa);

    return cipher;
}



/////////////////////////////////////////////////////////////////////////
// generateKeyPairRsa()
RsaKey* generateKeyPairRsa(int keySize, int exponent)
{
    RsaKey*     key;
    int         sc;

    key = (RsaKey*)wcjs_alloc(sizeof(RsaKey));
    FATAL(!key);

    sc = wc_MakeRsaKey(key, keySize, exponent, &rng);
    FATAL(sc != 0);

    return key;
}


/////////////////////////////////////////////////////////////////////////
// generateKeyPair()
uint8_t* generateKeyPair(int keySize, int exponent)
{
    RsaKey* rsa;
    uint8_t* der;
    uint8_t* pem, *p;
    int      sc, derLen, pemLen;

    rsa = generateKeyPairRsa(keySize, exponent);
    FATAL(!rsa);

    derLen = 2048;
    der = wcjs_alloc(derLen); /* max size */
    FATAL(!der);

    pemLen = 2048;
    pem = wcjs_alloc(pemLen); /* max size */
    FATAL(!pem);

    p = pem;

    /* export public with null term */
    sc = wc_RsaKeyToPublicDer(rsa, der, derLen);
    FATAL(sc < 0);
    derLen = sc;

    sc = wc_DerToPem(der, derLen, p, pemLen, PUBLICKEY_TYPE);
    FATAL(sc < 0);

    p[sc] = '\0';
    p += sc + 1;
    pemLen -= sc + 1;


    /* export private with null term */
    derLen = 2048;
    sc = wc_RsaKeyToDer(rsa, der, derLen);
    FATAL(sc < 0);
    derLen = sc;

    sc = wc_DerToPem(der, derLen, p, pemLen, PRIVATEKEY_TYPE);
    FATAL(sc < 0);

    p[sc] = '\0';

    wcjs_free(der);

    wc_FreeRsaKey(rsa);
    wcjs_free(rsa);

    return pem;
}

#endif /* !NO_RSA */

/////////////////////////////////////////////////////////////////////////
// generateKey
uint8_t* generateKey(void)
{
    return randomBytesAlloc(256/8);
}



/////////////////////////////////////////////////////////////////////////
// init()
int init(void)
{
    int sc;
#ifdef CONFIG_DEBUG
    ALLOCS=0;

    XLOG("init\n");
#endif

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    wolfCrypt_Init();

    /* setup RNG */
    sc = wc_InitRng(&rng);
    printf("wc_InitRng ret=%d\n", sc);
    FATAL(sc != 0);

    return 1;

}

/////////////////////////////////////////////////////////////////////////
// deinit()
int deinit(void)
{
    wc_FreeRng(&rng);

    wolfCrypt_Cleanup();

#ifdef CONFIG_DEBUG
    XLOG("#ALLOCS: %d\n", ALLOCS);
#endif

    return 1;
}
