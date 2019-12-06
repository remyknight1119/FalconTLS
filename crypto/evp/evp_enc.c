
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

int
FC_EVP_CIPHER_CTX_reset(FC_EVP_CIPHER_CTX *c)
{
    return EVP_CIPHER_CTX_reset((EVP_CIPHER_CTX *)c);
}

FC_EVP_CIPHER_CTX *
FC_EVP_CIPHER_CTX_new(void)
{
    return (EVP_CIPHER_CTX *)EVP_CIPHER_CTX_new();
}

void
FC_EVP_CIPHER_CTX_free(FC_EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)ctx);
}

int
FC_EVP_CipherInit(FC_EVP_CIPHER_CTX *ctx, const FC_EVP_CIPHER *cipher,
        const unsigned char *key, const unsigned char *iv, int enc)
{
    return EVP_CipherInit((EVP_CIPHER_CTX *)ctx, (const EVP_CIPHER *)cipher,
            key, iv, enc);
}

int
FC_EVP_CipherInit_ex(FC_EVP_CIPHER_CTX *ctx, const FC_EVP_CIPHER *cipher,
        FC_ENGINE *impl, const unsigned char *key,
        const unsigned char *iv, int enc)
{
    return EVP_CipherInit_ex((EVP_CIPHER_CTX *)ctx, (const EVP_CIPHER *)cipher,
            (ENGINE *)impl, key, iv, enc);
}

int
FC_EVP_CIPHER_CTX_ctrl(FC_EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx, type, arg, ptr);
}
