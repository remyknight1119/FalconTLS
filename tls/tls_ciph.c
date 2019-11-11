
#include <falcontls/types.h>
#include <fc_log.h>
#include "tls_locl.h"

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

const FC_EVP_MD *
tls_prf_md(TLS *s)
{
    return tls_md(tls_get_algorithm(s) >> TLS1_PRF_DGST_SHIFT);
}

const TLS_CIPHER *
tls_search_cipher_byid(const TLS_CIPHER *ciphers, size_t num, uint32_t id)
{
    const TLS_CIPHER    *cipher = NULL;
    int                 i = 0;

    for (i = 0; i < num; i++) {
        cipher = &ciphers[i];
        if (cipher->cp_id == id) {
            return cipher;
        }
    }

    FC_LOG("find cipher failed\n");
    return NULL;
}

int 
tls_put_cipher_by_char(const TLS_CIPHER *c, WPACKET *pkt, size_t *len)
{
    if (!WPACKET_put_bytes_u16(pkt, c->cp_id & 0xffff)) {
        return 0;
    }

    *len = sizeof(uint16_t);
    return 1;
}


