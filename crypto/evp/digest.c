
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>


FC_EVP_MD_CTX *
FC_EVP_MD_CTX_new(void)
{
    return (FC_EVP_MD_CTX *)EVP_MD_CTX_new();
}

void
FC_EVP_MD_CTX_free(FC_EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
}

int
FC_EVP_MD_CTX_copy_ex(FC_EVP_MD_CTX *out, const FC_EVP_MD_CTX *in)
{
    return EVP_MD_CTX_copy_ex((EVP_MD_CTX *)out, (const EVP_MD_CTX *)in);
}

int
FC_EVP_DigestFinal_ex(FC_EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    return EVP_DigestFinal_ex((EVP_MD_CTX *)ctx, md, size);
}

int
FC_EVP_DigestInit_ex(FC_EVP_MD_CTX *ctx, const FC_EVP_MD *type, FC_ENGINE *impl)
{
    return EVP_DigestInit_ex((EVP_MD_CTX *)ctx, (const EVP_MD *)type,
                    (ENGINE *)impl);
}

int
FC_EVP_DigestUpdate(FC_EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, count);
}
