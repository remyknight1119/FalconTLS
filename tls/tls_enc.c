

#include "tls_locl.h"
#include "tls1.h"
#include "handshake.h"
#include "cipher.h"


int
tls_digest_cached_records(TLS *s, int keep)
{
    const FC_EVP_MD     *md = NULL;
    void                *hdata = NULL;
    long                hdatalen = 0;

    if (s->tls_state.st_handshake_dgst == NULL) {
        hdatalen = FC_BIO_get_mem_data(s->tls_state.st_handshake_buffer, &hdata);
        if (hdatalen <= 0) {
            return 0;
        }

        s->tls_state.st_handshake_dgst = EVP_MD_CTX_new();
        if (s->tls_state.st_handshake_dgst == NULL) {
            return 0;
        }

        md = tls_handshake_md(s);
        if (md == NULL || !FC_EVP_DigestInit_ex(s->tls_state.st_handshake_dgst, md, NULL)
                || !FC_EVP_DigestUpdate(s->tls_state.st_handshake_dgst, hdata, hdatalen)) {
            return 0;
        }
    }

    if (keep == 0) {
        FC_BIO_free(s->tls_state.st_handshake_buffer);
        s->tls_state.st_handshake_buffer = NULL;
    }

    return 1;
}

