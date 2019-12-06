
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

int 
FC_EVP_MD_size(const FC_EVP_MD *md)
{
    return EVP_MD_size((const EVP_MD *)md);
}

int
FC_EVP_CIPHER_key_length(const FC_EVP_CIPHER *cipher)
{
    return EVP_CIPHER_key_length((const EVP_CIPHER *)cipher);
}

int
FC_EVP_CIPHER_iv_length(const FC_EVP_CIPHER *cipher)
{
    return EVP_CIPHER_iv_length((const EVP_CIPHER *)cipher);
}

unsigned long
FC_EVP_CIPHER_flags(const FC_EVP_CIPHER *cipher)
{
    return EVP_CIPHER_flags((const EVP_CIPHER *)cipher);
}

