#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

int
FC_EVP_PKEY_derive_init(FC_EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_derive_init((EVP_PKEY_CTX *)ctx);
}

int
FC_EVP_PKEY_derive_set_peer(FC_EVP_PKEY_CTX *ctx, FC_EVP_PKEY *peer)
{
    return EVP_PKEY_derive_set_peer((EVP_PKEY_CTX *)ctx, (EVP_PKEY *)peer);
}

int
FC_EVP_PKEY_derive(FC_EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen)
{
    return EVP_PKEY_derive((EVP_PKEY_CTX *)ctx, key, pkeylen);
}
