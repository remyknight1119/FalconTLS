
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

void
FC_EVP_PKEY_free(FC_EVP_PKEY *x)
{
    EVP_PKEY_free((void *)x);
}

int
FC_EVP_PKEY_set1_tls_encodedpoint(FC_EVP_PKEY *pkey,
                    const unsigned char *pt, size_t ptlen)
{
    return EVP_PKEY_set1_tls_encodedpoint((EVP_PKEY *)pkey, pt, ptlen);
}

int
FC_EVP_PKEY_id(const FC_EVP_PKEY *pkey)
{
    return EVP_PKEY_id((const EVP_PKEY *)pkey);
}

FC_EC_KEY *
FC_EVP_PKEY_get0_EC_KEY(FC_EVP_PKEY *pkey)
{
    return (FC_EC_KEY *)EVP_PKEY_get0_EC_KEY((EVP_PKEY *)pkey);
}

int
FC_EVP_PKEY_up_ref(FC_EVP_PKEY *pkey)
{
    return EVP_PKEY_up_ref((EVP_PKEY *)pkey);
}

size_t
FC_EVP_PKEY_get1_tls_encodedpoint(FC_EVP_PKEY *pkey, unsigned char **ppt)
{
    return EVP_PKEY_get1_tls_encodedpoint((EVP_PKEY *)pkey,
            (unsigned char **)ppt);
}
