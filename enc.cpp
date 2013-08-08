#include "enc.h"
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>



static int32_t fib_seeds[20] = 
{
    1,2,3,5,9,1,2,7,1,3,5,6,7,8,8,9,3,7,4,6
};

static const char * aes_ukey = "\x16\x25\x3a\x48\x55\x69\x77\x8c\x94\xa7\xbe\xc1\xd4\xe2\xfd\x11";

// 设计这种混淆算法简直是脑残，另外，你们设计了3种，为什么只用了一种呢？
static bool xor_fibonacci_crypt(void * buffer, size_t len, int cipher_num)
{
    int64_t a, b, seed1, seed2;
    uint8_t c;
    int i;
    char * cbuffer = (char *) buffer;

    if(cipher_num <= 0 || cipher_num > 10 || NULL == cbuffer)
        return false;

    seed1 = fib_seeds[(cipher_num - 1) * 2];
    seed2 = fib_seeds[(cipher_num - 1) * 2 + 1];

    for(i = 0 ; i < len; i ++) {
            a = seed1 + seed2;
            b = a * 2155905153UL;
            b = b >> 39;
            b = b * 255;
            a = a - b;
            c = a & 0xFF;
            seed1 = seed2;
            seed2 = c;
            cbuffer[i] ^= c;
    }
    return true;
}

// 这也很恼残，任何一个块加密算法都可以当流式用，不需要各种padding，aes-cfb啥的听说过么？
// 而且，即使用分块，为毛不用cbc之类的模式呢？一块一块裸搞，基本没有啥安全性
static bool aes_block_encrypt(void * buffer, size_t len)
{
    AES_KEY key;
    char out[16];
    size_t bc = len / 16;
    char *cbuf = (char *)buffer;

    if(NULL == buffer || len % 16 != 0)
        return false;

    AES_set_encrypt_key((const unsigned char*)aes_ukey, 128, &key);

    for(size_t i = 0 ; i < bc ; i ++) {
        AES_encrypt((const unsigned char*)(cbuf + i * 16), (unsigned char*)out, &key);
        memcpy(cbuf + i * 16, out, 16);
    }
    return true;
}

static bool aes_block_decrypt(void * buffer, size_t len)
{
    AES_KEY key;
    char out[16];
    size_t bc = len / 16;
    char *cbuf = (char *)buffer;

    if(NULL == buffer || len % 16 != 0)
        return false;

    AES_set_decrypt_key((const unsigned char*)aes_ukey, 128, &key);

    for(size_t i = 0 ; i < bc ; i ++) {
        AES_decrypt((const unsigned char*)(cbuf + i * 16), (unsigned char*)out, &key);
        memcpy(cbuf + i * 16, out, 16);
    }
    return true;
}

bool enc_buffer(void * buffer, size_t real_len, size_t total_len, int cipher_num)
{
    if(real_len > total_len || buffer == NULL)
        return false;

    if(total_len % 16 != 0)
        return false;

    if(!xor_fibonacci_crypt(buffer, real_len, cipher_num)) {
        return false;
    }

    if(!aes_block_encrypt(buffer,total_len)) {
        return false;
    }
    
    return true;
}

bool dec_buffer(void * buffer, size_t real_len, size_t total_len, int cipher_num)
{
    if(real_len > total_len || buffer == NULL)
        return false;

    if(total_len % 16 != 0)
        return false;

    if(!aes_block_decrypt(buffer,total_len)) {
        return false;
    }

    if(!xor_fibonacci_crypt(buffer, real_len, cipher_num)) {
        return false;
    }

    return true;
}

bool rsa_enc_pass(const std::string & pass, std::string & enc_pass)
{
    static const char * n_str =
    "00ac3a16cd5c00e7e36bd67ec973322a5f3e3525d4152d84b984f7ea40dc82f33"
    "70658df7e2b833987a5b7945e8f5cb2c8ab9623cf81d9c3b89ac1c72dc470295b"
    "82fe940fe2611e5aa98433c669ff29a25ba4018c3ed501f56578d79f7f53dd2a7"
    "3180847671ecefcfd720f1d5d5fb9b6840fc3060501ea376e36549e865f3e0957"
    "f35cc02c8398ee753dc75cf7e922049b7e8d08d982fef2e72a2267cb261f418a7"
    "fac0e4cbdf027e2e9154d8c0d8146fdd55eed65c5f0ba8d8e894f626a7df9ed5c"
    "addd4cc120948ff384a36364eb966b8abe4fb09b39833446a4f12ec84238f3eef"
    "faa3f2dc6849a4f5f6c01894e4f5294de5445c93386f68e0a161f716611";

    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    int pass_len = 0;
    int i = 0;
    bool success = false;
    char * enc_pass_buffer = NULL;
    char * enc_pass_str = NULL;

    n = BN_new();
    e = BN_new();

    if(!n || !e)
        goto err;

    if(!BN_hex2bn(&n, n_str))
        goto err;

    if(!BN_set_word(e, 65537))
        goto err;

    if((rsa = RSA_new()) == NULL)
        goto err;

    rsa->n = n;
    rsa->e = e;

    pass_len = RSA_size(rsa);

    if(!(enc_pass_buffer = (char *)malloc(pass_len)))
        goto err;
    memset(enc_pass_buffer, 0, pass_len);

    if((pass_len = RSA_public_encrypt(pass.size(), (const unsigned char*)pass.data(), 
        (unsigned char*)enc_pass_buffer, rsa, RSA_PKCS1_PADDING)) < 0)
        goto err;

    if(!(enc_pass_str = (char *)malloc(pass_len*2+1)))
        goto err;
    memset(enc_pass_str, 0, pass_len*2+1);

    for(i = 0; i < pass_len; i ++) {
        sprintf(enc_pass_str+i*2, "%02hhx", (unsigned char)enc_pass_buffer[i]);
    }

    enc_pass = enc_pass_str;

    success = true;
err:
    if(n) BN_free(n);
    if(e) BN_free(e); 
    if(rsa) {
        rsa->n = NULL;
        rsa->e = NULL;
        RSA_free(rsa);
    }
    if(enc_pass_buffer) free(enc_pass_buffer);
    if(enc_pass_str) free(enc_pass_str);
    return success;
}
