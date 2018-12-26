
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

int
FC_EVP_PKEY_paramgen_init(FC_EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_paramgen_init((void *)ctx);
}

int
FC_EVP_PKEY_paramgen(FC_EVP_PKEY_CTX *ctx, FC_EVP_PKEY **ppkey)
{
    return EVP_PKEY_paramgen((void *)ctx, (EVP_PKEY **)ppkey); 
}
