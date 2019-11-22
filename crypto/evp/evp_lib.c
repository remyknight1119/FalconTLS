
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

int 
FC_EVP_MD_size(const FC_EVP_MD *md)
{
    return EVP_MD_size((const EVP_MD *)md);
}
