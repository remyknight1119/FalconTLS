
#include <falcontls/types.h>

#define TLS_MD_NUM_IDX  TLS_MAX_DIGEST

static const FC_EVP_MD *tls_digest_methods[TLS_MD_NUM_IDX];


const FC_EVP_MD *
tls_md(int idx)
{
    idx &= TLS_HANDSHAKE_MAC_MASK;
    if (idx < 0 || idx >= TLS_MD_NUM_IDX) {
        return NULL;
    }

    return tls_digest_methods[idx];
}

const FC_EVP_MD *
tls_handshake_md(TLS *s)
{
    return tls_md(tls_get_algorithm(s));
}
