
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

FC_EVP_PKEY_CTX *
FC_EVP_PKEY_CTX_new_id(int id, FC_ENGINE *e)
{
    return (void *)EVP_PKEY_CTX_new_id(id, (ENGINE *)e);
}

int
FC_EVP_PKEY_CTX_ctrl(FC_EVP_PKEY_CTX *ctx, int keytype, int optype,
            int cmd, int p1, void *p2)
{
    return EVP_PKEY_CTX_ctrl((void *)ctx, keytype, optype, cmd, p1, p2);
}

FC_EVP_PKEY_CTX *
FC_EVP_PKEY_CTX_new(FC_EVP_PKEY *pkey, FC_ENGINE *e)
{
    return (void *)EVP_PKEY_CTX_new((EVP_PKEY *)pkey, (ENGINE *)e);
}

void
FC_EVP_PKEY_CTX_free(FC_EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_CTX_free((void *)ctx);
}
