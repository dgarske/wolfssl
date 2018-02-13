#include "wcjs.h"
#include <stdio.h>
#include <stdint.h>


/////////////////////////////////////////////////////////////////////////
int test_cryptor(void)
{
    uint8_t key[256/8]  = {};
    uint8_t iv[256/8]   = {};
    int sc = 1, i;

    for (i=0; i<1000; i++) {
        uint8_t*    plain1;
        size_t      plain1Len;
        uint8_t*    plain2;
        size_t      plain2Len;

        uint8_t*    cipher;
        size_t      cipherLen;

        randomBytes(key, sizeof(key));
        randomBytes(iv, sizeof(iv));

        plain1Len = randInt(100);
        plain1 = randomBytesAlloc(plain1Len);
        cipher = encryptor(plain1, plain1Len, key, iv, &cipherLen, 0, NULL);
        plain2 = decryptor(cipher, cipherLen, key, iv, &plain2Len, 0, NULL);

        if (memcmp(plain1, plain2, plain1Len) != 0) {
            sc = -1;
        }

        wcjs_free(plain1);
        wcjs_free(plain2);
        wcjs_free(cipher);
    }
    printf("ALL PASSED!\n");

    return sc;
}

/////////////////////////////////////////////////////////////////////////
int test_hmac(void)
{
    char*       key     = "Jefe";
    char*       plainIn = "what do ya want for nothing?";
    const char* hashOut = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    uint8_t*    cipher;
    size_t      digestLen;
    int         sc = 1;

    printf("Testing hmac()...\n");

    cipher = hmac((uint8_t*)plainIn, strlen(plainIn),
        (uint8_t*)key, strlen(key), &digestLen);

    if (memcmp(cipher, hashOut, strlen(hashOut)) != 0) {
        printf("Should match: %s\n", hashOut);
        sc = -1;
    }

    wcjs_free(cipher);

    return sc;
}

/////////////////////////////////////////////////////////////////////////
int test_prng(void)
{
    uint8_t* bytes = randomBytesAlloc(32);
    int i;

    printf("prng: ");
    printf("\n");
    wcjs_free(bytes);

    for (i=0; i<100; i++) {
        unsigned int r = randInt(100);
        printf("%d ", r );
    }
    printf("\n");

    return 1;
}


int main(int argc, char* argv[])
{
    int         sc;
    int i;

    typedef int (*Tester)();

    Tester testers[] = {
        test_hmac,
        test_cryptor,
        test_prng,
        NULL
    };

    printf("running...\n");

    init();

    for (i=0; testers[i] != NULL; i++) {
        sc = testers[i]();
        if (sc > 0) {
            printf("[%d] PASSED!\n", i );
        }
        else {
            printf("[%d] !FAILED!\n", i );
        }
    }

    return 0;
}
