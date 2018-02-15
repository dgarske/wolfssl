LEVEL := ..

include $(LEVEL)/Makefile.config

tester: wcjs-node.js
	node wcjswrap-test-node.js

wcjs_wolfcrypt: objects/aes.o objects/asn.o objects/chacha.o objects/chacha20_poly1305.o objects/cmac.o objects/coding.o objects/curve25519.o objects/des3.o objects/dh.o objects/ecc.o objects/ed25519.o objects/error.o objects/fe_low_mem.o objects/fe_operations.o objects/ge_low_mem.o objects/ge_operations.o objects/hash.o objects/hmac.o objects/integer.o objects/logging.o objects/md5.o objects/memory.o objects/pkcs7.o objects/pkcs12.o objects/poly1305.o objects/pwdbased.o objects/random.o objects/rsa.o objects/sha.o objects/sha256.o objects/sha3.o objects/sha512.o objects/signature.o objects/tfm.o objects/wc_encrypt.o objects/wc_port.o objects/wolfmath.o
wcjs_wolfssl: objects/crl.o objects/internal.o objects/keys.o objects/ocsp.o objects/ssl.o objects/tls.o objects/tls13.o objects/wolfio.o

wcjs-node.js: objects/wcjs.o wcjs_wolfcrypt wcjs_wolfssl
	emcc $(CFLAGS) -s EXPORTED_FUNCTIONS=$(EXPORTED_FUNCTIONS) \
	    objects/aes.o objects/asn.o objects/chacha.o objects/chacha20_poly1305.o objects/cmac.o objects/coding.o objects/curve25519.o objects/des3.o objects/dh.o objects/ecc.o objects/ed25519.o objects/error.o objects/fe_low_mem.o objects/fe_operations.o objects/ge_low_mem.o objects/ge_operations.o objects/hash.o objects/hmac.o objects/integer.o objects/logging.o objects/md5.o objects/memory.o objects/pkcs7.o objects/pkcs12.o objects/poly1305.o objects/pwdbased.o objects/random.o objects/rsa.o objects/sha.o objects/sha256.o objects/sha3.o objects/sha512.o objects/signature.o objects/tfm.o objects/wc_encrypt.o objects/wc_port.o objects/wolfmath.o \
	    objects/crl.o objects/internal.o objects/keys.o objects/ocsp.o objects/ssl.o objects/tls.o objects/tls13.o objects/wolfio.o \
	    objects/wcjs.o \
	    -o wcjs-node.js

wcjs.js: objects/wcjs.o wcjs_wolfcrypt wcjs_wolfssl
	emcc $(CFLAGS) -s EXPORTED_FUNCTIONS=$(EXPORTED_FUNCTIONS) \
		--separate-asm \
	    objects/aes.o objects/asn.o objects/chacha.o objects/chacha20_poly1305.o objects/cmac.o objects/coding.o objects/curve25519.o objects/des3.o objects/dh.o objects/ecc.o objects/ed25519.o objects/error.o objects/fe_low_mem.o objects/fe_operations.o objects/ge_low_mem.o objects/ge_operations.o objects/hash.o objects/hmac.o objects/integer.o objects/logging.o objects/md5.o objects/memory.o objects/pkcs7.o objects/pkcs12.o objects/poly1305.o objects/pwdbased.o objects/random.o objects/rsa.o objects/sha.o objects/sha256.o objects/sha3.o objects/sha512.o objects/signature.o objects/tfm.o objects/wc_encrypt.o objects/wc_port.o objects/wolfmath.o \
	    objects/crl.o objects/internal.o objects/keys.o objects/ocsp.o objects/ssl.o objects/tls.o objects/tls13.o objects/wolfio.o \
	    objects/wcjs.o \
	    -o wcjs.js

wcjsgen: wcjs.js

	# convert emscripten code to single line, remove commenting
	#uglifyjs wcjs.js --output wcjs_s.js

	# convert asm (wolfCrypt) to single line, remove commenting
	# cat wcjs.asm.js | jsesc --double-quotes --wrap > wcjs.asm.js.txt

	#uglifyjs wcjs.asm.js --output wcjs.asm_s.js
	#cat wcjs.asm_s.js | jsesc --double-quotes --wrap > wcjs.asm_s.js.txt

	# replace these in the template with actual files
	# VAR_WCJS_S_ASM_JS -> wcjs_s.asm.js
	# VAR_WCJS_S_JS -> wcjs_s.js
	# VAR_WCJSWRAP_JS -> wcjswrap.js
	# VAR_WCJSSWRAP_TEST_JS -> wcjswrap-test.js

	cp wolfcrypt_template.js wolfcrypt.js
	gsed -e '/VAR_WCJS_ASM_JS/ {' -e 'r wcjs.asm.js' -e 'd' -e '}' -i wolfcrypt.js
	gsed -e '/VAR_WCJS_JS/ {' -e 'r wcjs.js' -e 'd' -e '}' -i wolfcrypt.js
	gsed -e '/VAR_WCJSWRAP_JS/ {' -e 'r wcjswrap.js' -e 'd' -e '}' -i wolfcrypt.js
	gsed -e '/VAR_WCJSWRAP_TEST_JS/ {' -e 'r wcjswrap-test.js' -e 'd' -e '}' -i wolfcrypt.js


wcjslib.js: objects/wcjslib.o
	emcc $(CFLAGS) -s EXPORTED_FUNCTIONS=$(EXPORTED_FUNCTIONS) \
	    objects/wcjslib.o \
	    -o wcjslib.js


# wolfCrypt
objects/aes.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/aes.c
objects/asn.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/asn.c
objects/chacha.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/chacha.c
objects/chacha20_poly1305.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/chacha20_poly1305.c
objects/cmac.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/cmac.c
objects/coding.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/coding.c
objects/curve25519.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/curve25519.c
objects/des3.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/des3.c
objects/dh.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/dh.c
objects/ecc.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/ecc.c
objects/ed25519.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/ed25519.c
objects/error.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/error.c
objects/fe_low_mem.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/fe_low_mem.c
objects/fe_operations.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/fe_operations.c
objects/ge_low_mem.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/ge_low_mem.c
objects/ge_operations.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/ge_operations.c
objects/hash.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/hash.c
objects/hmac.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/hmac.c
objects/integer.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/integer.c
objects/logging.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/logging.c
objects/md5.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/md5.c
objects/memory.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/memory.c
objects/pkcs7.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/pkcs7.c
objects/pkcs12.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/pkcs12.c
objects/poly1305.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/poly1305.c
objects/pwdbased.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/pwdbased.c
objects/random.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/random.c
objects/rsa.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/rsa.c
objects/sha.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/sha.c
objects/sha256.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/sha256.c
objects/sha3.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/sha3.c
objects/sha512.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/sha512.c
objects/signature.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/signature.c
objects/tfm.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/tfm.c
objects/wc_encrypt.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/wc_encrypt.c
objects/wc_port.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/wc_port.c
objects/wolfmath.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/wolfcrypt/src/wolfmath.c


# wolfSSL
objects/crl.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/crl.c
objects/internal.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/internal.c
objects/keys.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/keys.c
objects/ocsp.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/ocsp.c
objects/ssl.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/ssl.c
objects/tls.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/tls.c
objects/tls13.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/tls13.c
objects/wolfio.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $(WOLFSSL)/src/wolfio.c

# emcc
objects/wcjs.o: wcjs.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

objects/wcjslib.o: wcjs.c
	$(CC) $(CFLAGS_LIB) $(INCLUDES_LIB) -c -o $@ $< -l wolfssl -L ../local/lib

# native
objects/wcjs_native.o: wcjs.c
	$(CC) $(CFLAGS_LIB) $(INCLUDES_LIB) \
		-ferror-limit=0 \
		-c -o $@ $< -l wolfssl -L ../local/lib

wcjs-test: wcjs-test.c objects/wcjs_native.o
	$(CC) $(CFLAGS_LIB) $(INCLUDES_LIB) objects/wcjs_native.o $< -o $@ -l wolfssl -L ../local/lib -lm


clean:
	rm -f $(OBJS) objects/*.o $(CMD) hello wcjs wcjs.js wcjs-test wcjs.js.mem wcjs.asm.js wcjs.asm_s.js wcjs.asm_s.js.txt wcjs_s.asm.js wcjs-node.js
