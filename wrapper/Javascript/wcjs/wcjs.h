#include "wcjslogging.h"

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn_public.h>


#define AES_KEY_SIZE        (256/8)
#define BLOCK_SIZE          (128/8)
#define AES_IV_SIZE         (128/8)
#define MODE_AES_256_CBC    1
#define MODE_AES_256_GCM    0
#define RSA_PADDING         WC_RSA_PKCSV15_PAD

#define RSA_KEYBITS         2048
#define RSA_E               0x10001
#define TAG_SIZE            (16)

int         init(void);
int         deinit(void);

uint8_t*    sha256(uint8_t* buf, size_t bufLen);
RsaKey*     generateKeyPairRsa(int keySize, int exponent);
int         randomBytes(void* bytes, int len);
size_t      pkcs7_unpad(uint8_t* in, size_t len);
uint8_t*    decryptWithPrivateKey(uint8_t* keyPem, uint8_t* cipher, int cipherLen, int* plainLen);
uint8_t*    decryptor(uint8_t* input, size_t inputLen, uint8_t* key, uint8_t* iv, size_t* outputLen, int cipherMode, uint8_t tag[TAG_SIZE]);
uint8_t*    encryptWithPublicKey(uint8_t* keyPem, uint8_t* plain, int plainLen, int* cipherLen);
uint8_t*    encryptor(uint8_t* input, size_t inputLen, uint8_t* key, uint8_t* iv, size_t* outputLen, int cipherMode, uint8_t tag[TAG_SIZE]);
uint8_t*    generateInitializationVector(size_t length);
uint8_t*    generateKey();
uint8_t*    generateKeyPair (int keySize, int exponent);
uint8_t*    hmac(uint8_t* input, size_t inputLen, uint8_t* key, size_t keyLen, size_t* digestLen);
uint8_t*    randomBytesAlloc(int len);
uint32_t    randInt(unsigned int max);

void        wcjs_free(void* ptr);
void*       wcjs_alloc(size_t sz);

void        hexdump(FILE * stream, void const * data, unsigned int len);
