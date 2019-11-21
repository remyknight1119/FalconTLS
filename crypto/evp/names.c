
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

const FC_EVP_CIPHER *
FC_EVP_get_cipherbynid(int nid)
{
    return (FC_EVP_CIPHER *)EVP_get_cipherbynid(nid);
}

const FC_EVP_MD *
FC_EVP_get_digestbynid(int nid)
{
    return (FC_EVP_MD *)EVP_get_digestbynid(nid);
}

