
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

void
FC_EVP_PKEY_free(FC_EVP_PKEY *x)
{
    EVP_PKEY_free((void *)x);
}

