var TAG_SIZE = 16;

/////////////////////////////////////////////////////////////////////////
// stringToArrayBuffer()
function stringToArray(str)
{
    var ret = new Uint8Array(str.length);

    for (var i=0; i< str.length; i++) {
        ret[i] = str.charCodeAt(i)
    }

    return ret;
}

/////////////////////////////////////////////////////////////////////////
// arrayToString()
function arrayToString(arr)
{
    var ret = String.fromCharCode.apply(null, new Uint8Array(arr));
    return ret;
}


/////////////////////////////////////////////////////////////////////////
function arrayRandom(length)
{
    var arr = new Uint8Array(length);
    for (var i=0; i<length; i++) {
        arr[i] = Math.random()*0xFF;
    }
    return arr;
}


/////////////////////////////////////////////////////////////////////////
function arraysEqual(a, b)
{
    if (a.length !== b.length) {
        return false;
    }

    for (var i=0; i<a.length; i++) {
        if (a[i] !== b[i])
            return false;
    }
    return true;
}


/////////////////////////////////////////////////////////////////////////
// dumpHex()
dumpHex = function(buf, len, cols)
{
    cols = cols | 8;
    var msg = "";

    console.log(typeof(buf) +' len: '+ len);
    for (var i=0; i<len; i++) {
        var val;

        switch (typeof(buf)) 
        {
            case 'string':
                val = buf.charCodeAt(i) & 0xFF;
                break;
            case 'number':
                val = wc.getValue(buf+i, 'i8') &0xff;
                break;
            case 'object':
                val = buf[i] & 0xFF;
                break;
            default:
                throw("dumpHex type error");
        }

        val = val.toString(16) +'';

        msg += " " + val;
        if (i % cols == cols-1) {
            console.log(msg);
            msg = "";
        }
    }
    console.log(msg);
}


/////////////////////////////////////////////////////////////////////////
// arrayToPointer()
arrayToPointer = function(arr)
{
    var arrayHeap;
    var ptr;

    ptr = xalloc(arr.length);
    arrayHeap = new Uint8Array(wc.HEAPU8.buffer, ptr, arr.length);
    arrayHeap.set(arr);
    return ptr;
}

/////////////////////////////////////////////////////////////////////////
// pointerToArray()
pointerToArray = function(ptr, length)
{
    var ret;

    ret = new Uint8Array(wc.HEAPU8.buffer, ptr, length);
    if (ret===0 || ret===undefined)
        throw("Unable to alloc buffer");
    ret = Uint8Array.from(ret);
    if(ret===0 || ret===undefined)
        throw("Unable to alloc buffer");
    return ret;
}

/////////////////////////////////////////////////////////////////////////
// stringToPointer()
stringToPointer = function(str)
{
    var ret = undefined;
    if (str == undefined)
        return ret;
    var len = wc.lengthBytesUTF8(str)
    ret = xalloc(len);
    if (ret===0 || ret===undefined)
        throw("Unable to alloc buffer");

    wc.stringToUTF8(str, ret, len);
    return ret;
}


/////////////////////////////////////////////////////////////////////////
//
randInt = function(max)
{
    return (Math.random()*max)&0xFFFFffff;
}



/////////////////////////////////////////////////////////////////////////
// alloc()
xalloc = function(len)
{
    return wc._wcjs_alloc(len);
}

/////////////////////////////////////////////////////////////////////////
// xfree()
xfree = function(ptr, name)
{
    if (ptr !== undefined && ptr !== 0) {
        try {
            wc._wcjs_free(ptr);
        }
        catch(x) {
            throw("free error")
        }
    }
    else {
        throw("!!!!!!!!!!!!!!!NULL FREE");
    }

}


/////////////////////////////////////////////////////////////////////////
// maxunpad
maxunpad = function(plain)
{
    var outlen = plain.length + 16 - (plain.length%16);
    var padlen = plain.length - outlen;
    var ret = new Uint8Array(outlen);
    ret.set(plain);

    return ret;
}


/////////////////////////////////////////////////////////////////////////
// maxipad
maxipad = function(plain)
{
    var outlen = plain.length + 16 - (plain.length%16);
    var padlen = outlen - plain.length;
    var ret = new Uint8Array(outlen);
    ret.set(plain);

    // Add padding bytes
    for (var i=plain.length; i<outlen; i++) {
        ret[i] = padlen;
    }

    return ret;

}

/////////////////////////////////////////////////////////////////////////
// encrypt
encrypt = function(plain, key, iv, mode)
{
    var     cipher;
    var     len;
    var     pcipher         = undefined;
    var     piv             = undefined;
    var     pkey            = undefined;
    var     plen            = undefined;
    var     pplain          = undefined;
    var     ptag            = undefined;

    if (mode == 1) {
        plain = maxipad(plain);
    }

    pplain  = arrayToPointer(plain, plain.length);
    pkey    = arrayToPointer(key,   key.length);
    piv     = arrayToPointer(iv,    iv.length);
    ptag    = xalloc(TAG_SIZE);
    plen    = xalloc(8);
    pcipher = wc._encryptor(pplain, plain.length, pkey, piv,  plen, mode, ptag);
    len     = wc.getValue(plen, 'i32');
    cipher  = pointerToArray(pcipher, len);
    tag     = pointerToArray(ptag, TAG_SIZE);

    xfree(pplain);
    xfree(pkey);
    xfree(piv);
    xfree(ptag);
    xfree(plen);
    xfree(pcipher);

    return  {
        cipher: cipher,
        tag: tag,
    };

}

/////////////////////////////////////////////////////////////////////////
// decrypt
decrypt = function(cipher, key, iv, mode, tag)
{

    var     len;
    var     pcipher     = undefined;
    var     piv         = undefined;
    var     pkey        = undefined;
    var     plain;
    var     plen        = undefined;
    var     pplain      = undefined;
    var     ptag        = undefined;

    pcipher = arrayToPointer(cipher,   cipher.length);
    pkey    = arrayToPointer(key,      key.length);
    piv     = arrayToPointer(iv,       iv.length);
    plen    = xalloc(8);
    ptag    = arrayToPointer(tag,      tag.length);
    pplain  = wc._decryptor(pcipher, cipher.length, pkey, piv, plen, mode, ptag);
    len     = wc.getValue(plen, 'i32');
    plain   = pointerToArray(pplain, len);

    xfree(pcipher);
    xfree(pkey);
    xfree(piv);
    xfree(plen);
    xfree(ptag);
    xfree(pplain);
    
    return plain;

}

/////////////////////////////////////////////////////////////////////////
// encryptWithPublicKey()
// encryptWithPublicKey(RSA* key, uint8_t* plain)
// keysize 2048, RSA_PKCS1_OAEP_PADDING
encryptWithPublicKey = function(key, plain)
{
    var     cipher;
    var     pcipher     = undefined;
    var     pkey        = undefined;
    var     plen        = undefined;
    var     pplain      = undefined;

    pkey    = stringToPointer(key);
    pplain  = arrayToPointer(plain, plain.length);
    plen    = xalloc(8);
    pcipher = wc._encryptWithPublicKey(pkey, pplain, plain.length, plen);
    len     = wc.getValue(plen, 'i32');
    cipher  = pointerToArray(pcipher, len);


    xfree(pkey);
    xfree(pplain);
    xfree(plen);
    xfree(pcipher);

    return cipher;
}


/////////////////////////////////////////////////////////////////////////
// decryptWithPrivateKey()
// Add support for private key decrypt w/ RSA_PKCS1_OAEP_PADDING
decryptWithPrivateKey = function(key, cipher)
{
    var     pcipher         = undefined;
    var     pkey            = undefined;
    var     plain;
    var     plen            = undefined;
    var     pplain          = undefined;


    pkey    = stringToPointer(key);
    pcipher = arrayToPointer(cipher,    cipher.length);
    plen    = xalloc(8);
    pplain  = wc._decryptWithPrivateKey(pkey, pcipher, cipher.length, plen);

    len     = wc.getValue(plen, 'i32');
    plain   = pointerToArray(pplain, len);

    xfree(pkey);
    xfree(pcipher);
    xfree(plen);
    xfree(pplain);

    return plain;
}


/////////////////////////////////////////////////////////////////////////
// randomBytes()
randomBytes = function(len)
{
    var     bytez;
    var     pbytez = undefined;

    pbytez  = wc._randomBytesAlloc(len);
    bytez   = pointerToArray(pbytez, len);

    xfree(pbytez);

    return bytez;
}

/////////////////////////////////////////////////////////////////////////
// generateInitializationVector()
generateInitializationVector = function()
{
    var     iv;
    var     len;
    var     piv = undefined;

    len     = 128/8;
    piv     = wc._generateInitializationVector(len);
    iv      = pointerToArray(piv, len);

    xfree(piv);

    return iv;
}

/////////////////////////////////////////////////////////////////////////
// generateKey()
generateKey = function()
{
    var     key;
    var     pKey = undefined;

    pKey    = wc._generateKey();
    key     = pointerToArray(pKey, 32);

    xfree(pKey);

    return key;
}

/////////////////////////////////////////////////////////////////////////
// generateKeyPair()
generateKeyPair = function(keySize, exponent)
{
    if(keySize===undefined)
        keySize = 2048;

    if(exponent===undefined)
        exponent = 0x10001;

    var ppair       = undefined;
    var pemPublic   = undefined;

    ppair       = wc._generateKeyPair(keySize, exponent);
    pemPublic   = wc.UTF8ToString(ppair);
    pemPrivate  = wc.UTF8ToString(ppair + pemPublic.length + 1);

    xfree(ppair);

    return {
        publicKey: pemPublic,
        privateKey: pemPrivate,
    };
}


/////////////////////////////////////////////////////////////////////////
// sha256()
sha256 = function(buf)
{

    var     md;
    var     pbuf    = undefined;
    var     pmd     = undefined;

    pbuf    = arrayToPointer(buf)
    pmd     = wc._sha256(pbuf, buf.length);
    md      = pointerToArray(pmd, 256/8);

    xfree(pbuf);
    xfree(pmd);

    return md;
}


/////////////////////////////////////////////////////////////////////////
// hmac()
hmac = function(inputArray, keyArray)
{
    var     digest;
    var     digestLen;
    var     pDigest         = undefined;
    var     pDigestLen      = undefined;
    var     pInput          = undefined;
    var     pKey            = undefined;

    pInput      = arrayToPointer(inputArray);
    pKey        = arrayToPointer(keyArray);
    pDigestLen  = xalloc(8);
    pDigest     = wc._hmac(pInput, inputArray.length, pKey, keyArray.length, pDigestLen);
    digestLen   = wc.getValue(pDigestLen, 'i32');
    digest      = pointerToArray(pDigest, digestLen)

    xfree(pInput);
    xfree(pKey);
    xfree(pDigest);
    xfree(pDigestLen);

    return digest;
}


/////////////////////////////////////////////////////////////////////////
// init()
init = function(code)
{
    wc._init();
}


/////////////////////////////////////////////////////////////////////////
// deinit()
deinit = function()
{
    xfree(gAsmCode);
    wc._deinit();
}
