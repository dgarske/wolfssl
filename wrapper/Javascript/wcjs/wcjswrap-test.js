var log     = console.log;

var PUB_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs81D2RJP58XFBtFStaYP
a/2w245HjDzZYqLcTcWhMK52bbO7+OhcjM9SMDqv8D8MqPghokOC2nHPS9Rly118
mHO03n9MsDd2kLE1PupIKG5tjd3umoRJ6rtP3lW1ne2KLEaKxg49LFUSzjw7AFnk
/PnhtZ1962rBLpDcRPaJf3JwFnz5/dI1BRdh5lpodl0alrgCO8choy7N9lDghKG6
5MVsYJgQMus4ZDwWihnV1O2mUsyPpi4LsIM1GVe65tPd6wSzoAKo+cXh4Q/Ai3gR
OB2jIasJuExSbw+FnCzGYHIjEkPty/d3Bn6ISlOK5YeML4Xp2i/RssUfpLH59UQR
TQIDAQAB
-----END PUBLIC KEY-----
`;

var PRIV_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzzUPZEk/nxcUG
0VK1pg9r/bDbjkeMPNliotxNxaEwrnZts7v46FyMz1IwOq/wPwyo+CGiQ4Lacc9L
1GXLXXyYc7Tef0ywN3aQsTU+6kgobm2N3e6ahEnqu0/eVbWd7YosRorGDj0sVRLO
PDsAWeT8+eG1nX3rasEukNxE9ol/cnAWfPn90jUFF2HmWmh2XRqWuAI7xyGjLs32
UOCEobrkxWxgmBAy6zhkPBaKGdXU7aZSzI+mLguwgzUZV7rm093rBLOgAqj5xeHh
D8CLeBE4HaMhqwm4TFJvD4WcLMZgciMSQ+3L93cGfohKU4rlh4wvhenaL9GyxR+k
sfn1RBFNAgMBAAECggEBAIMzT0UAtcn8aE8XQ3FFYY99qSYs5kyQwlfVW0hs47gw
Nj7Knml8tLwTNHf4+xUmDMjndzN+a+eWkJtWu4jwCND97YdGAOG9NwlSJfZo4oqO
OecBgPDDg2SDlj448LPy95ZjSzRGg6Dr2zMehDc3YX6voGH0MEQuvBSMpA62j5Ks
5wer0hj6P3kiZAMuOvRaB9eP0H/vH1Vpx+/XNLvInlz2JPJioZJ+K8wVqgvtpYux
zlSMWxW8J3KJqw2/0rEiurGoFpggnHsa57edROr1cZooy03X5WrkAflviDGv3fpm
OmOcUKPCbhJY2x1mts1hxEVjb+b451A1EX6vYwDH5cECgYEA5YFr3Hjh71NnVs0Z
xzydfVDr1ZXWGrpBSM066IeAycp+8gMRnJIrTdqpdKhBL3X+JTfTS8PiYz7Jpt71
zPQnG5eSVvYDDRGssGzwhiOCqJd++FWVh52pMyPs4Wb51SiYGNGTkr97IjiOQb8N
xVS2Q2F7GflCtF91LHYHtdkZkWUCgYEAyI7y729PUiuaEVe+hnedhjPdwQH5uXfE
J3tWNC92eWWfv4lOSUn3GGF1emu0ATqG0/iEVQj7Ul89WmmPkYEHorq6FST0ZWxm
emHyr9JVzkwXRD+I+vmJQwCRbtR8746oaWwnKbPlO7GgP5KjspfvKDKhULTHkNda
FygxmKLLNckCgYBExVFC0V4yTrWqhu7wirNOd88TQ0DS5XjmjcjXILNwxCLh9hVy
60HapGkescRGqn6rPF0uWNYfkxLt0+Wnsol9dR++ux0S73blrt8r8rwWNL8xPsP9
zTqEPoGe0TKPswhQd4xW7tXA3V2TSeKgfM/YxP8UO2LHlcsQtZV94j4NGQKBgQCH
syku1nquF3BkYaE5LH/6COf3KtYEJsQjDrGyF5cq5pbjKw08S36UEYVCctNVrXsC
u3kWbEBYaLaDkT8h7VL0STGVEu8GHQVtsw5Y5pFGR3fKps6ROfwkyKKegcmS8UyE
IDiTX/QvoqzRtu9p7KFV6oP5rogFOaDsYDbGlwe1+QKBgE5fF+dHKtuqaGHUXikq
QvOxDJsJJKTcafxh49UfV5oeRsKocoK09Gij+/4eLc1Ko8Vxw3gqTh3odVWb9FNj
USzhVrc+KZEn77dRg0sD1B6juJ0KcwHwoquzxAk3PuYA1AosONw+bnQAgEAmyWMG
ikykgWCinNEs8PvkmfFeFSzz
-----END PRIVATE KEY-----
`;


/////////////////////////////////////////////////////////////////////////
// test_rsa
test_rsa = function()
{
    console.log("Testing RSA...");
    console.log("===============================================================================")

    var     plainIn = "XXooXX", plainInArray;
    var     plainOut;
    var     cipher;

    plainInArray = stringToArray(plainIn);
    cipher       = encryptWithPublicKey(PUB_PEM, plainInArray);

    plainOut     = decryptWithPrivateKey(PRIV_PEM, cipher);
    plainOut     = arrayToString(plainOut);

    if (!arraysEqual(plainOut, plainIn)) {
        console.log("FAIL!");
        console.log('plainIn : |'+ plainIn.length  +"| :"+ plainIn);
        console.log('plainOut: |'+ plainOut.length +"| :"+ plainOut);
        return 0;
    }
    return 1;
}

/////////////////////////////////////////////////////////////////////////
// test_aes()
test_encrypt = function()
{
    console.log("Testing symmetric encryption...");
    console.log("===============================================================================")

    var     cipher;
    var     plainOut;
    var     failCnt = 0;
    var     iv;
    var     key;
    var     plainIn;
    var     encryptOut;
    var     tag;

    console.log("\tRunning iterations...");

    for (var mode=0; mode<=1; mode++) {
        console.log("\tTrying mode " + mode  + ".");
        for (var i=0; i<30; i++) {

            iv              = arrayRandom(128/8);
            key             = arrayRandom(256/8);
            plainIn         = arrayRandom(randInt(123));
            tag             = arrayRandom(16);

            if (i % 1000 == 0) {
                log("Iteration: " + i);
            }
            encryptOut      = encrypt(plainIn, key, iv, mode);
            cipher = encryptOut.cipher;
            tag = encryptOut.tag;

            plainOut        = decrypt(cipher,  key, iv, mode, tag);

            if (mode == 1) {
                plainOut = plainOut.slice(0, plainIn.length);
            }

            if (!arraysEqual(plainOut, plainIn)) {
                failCnt++;
                console.log("FAIL!");
                console.log('plainIn : |'+ plainIn.length  +"| :"+ plainIn);
                console.log('plainOut: |'+ plainOut.length +"| :"+ plainOut);
                return 0;
            }
        }
    }
    if (failCnt==0) {
        console.log("PASSED!");
    }
    console.log("There were " + failCnt + " failures and " + i + " passes.");

    return 1;
}


/////////////////////////////////////////////////////////////////////////
// test_sha256()
test_sha256 = function()
{
    console.log("Testing sha256...");
    console.log("===============================================================================")

    // "blink muted"
    var plain = [0x62, 0x6c, 0x69, 0x6e, 0x6b, 0x20, 0x6d, 0x75, 0x74, 0x65, 0x64];
    var target = [
        0x08, 0xc4, 0xa6, 0x79, 0x89, 0x29, 0x4c, 0x92,
        0xf7, 0x9d, 0xdc, 0x12, 0x8c, 0x3d, 0x74, 0xb3,
        0x9e, 0x19, 0x97, 0xf9, 0x52, 0x4c, 0x20, 0xe5,
        0xa0, 0xbb, 0x99, 0x0d, 0xbb, 0x8f, 0x9a, 0xec ];

    var md = sha256(plain);
    if (arraysEqual( target, md)) {
        return 1;
    } else {
        dumpHex(md, 265/8);
        return 0;
    }
}


/////////////////////////////////////////////////////////////////////////
// test_generateKey()
test_generateKey = function()
{
    console.log("Testing generateKey()...");

    for (i=0; i<10; i++) {
        var key = generateKey();
        dumpHex(key, 256/8, 32);
    }
    return 1;
}


/////////////////////////////////////////////////////////////////////////
// test_generateKeyPair()
test_generateKeyPair = function()
{
    console.log("Testing generateKeyPair()...");

    var pair;
    pair = generateKeyPair(512);

    console.log("public: " + pair.publicKey);
    console.log("private: " + pair.privateKey);

    return 1;
}


/////////////////////////////////////////////////////////////////////////
// test_hmac()
test_hmac = function()
{
    console.log("Testing hmac");
    console.log("===============================================================================")

    var cipher;
    var plainOut;

    var target = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
        0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
        0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    ];

    var failCnt = 0;

    /* minimum HMAC key length is 14 bytes */
    key = stringToArray("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");
    plainIn = stringToArray("Hi There");
    var res = hmac(plainIn, key);
    dumpHex(res, 32);

    if (!arraysEqual(target, res)) {
        console.log("FAIL!" + res);
        console.log("Should match: " + target);
        return 0;
    }
    return 1;
}


/////////////////////////////////////////////////////////////////////////
// test_generateInitializationVector
test_generateInitializationVector = function()
{
    console.log("Testing generateInitializationVector...");
    console.log("===============================================================================")

    var iv = generateInitializationVector();
    console.log("iv: " + iv);
    return 1;
}


/////////////////////////////////////////////////////////////////////////
// test_randomBytes
test_randomBytes = function()
{
    console.log("Testing randomBytes...");
    console.log("===============================================================================")

    var bytez = randomBytes(1000);
    console.log("randomBytes: " + bytez);
    return 1;
}


/////////////////////////////////////////////////////////////////////////
// entry_point()
entry_point = function()
{
    init();

    var tests = [
        test_encrypt,
        test_hmac,
        test_generateKey,
        test_randomBytes,
        test_sha256,
        test_generateInitializationVector,
        test_generateKeyPair,
        test_rsa,
    ];

    for (var i=0; i<tests.length; i++) {
        var test = tests[i];
        var sc = test();
        if (!sc) {
            console.log( "FAILED!!!");
            return;
        } else {
            console.log("-------------------- Passed! --------------------");
        }
        console.log("");
    }

    console.log("##########################################");
    console.log("Done!");
    console.log("##########################################");
    
    deinit();
}
