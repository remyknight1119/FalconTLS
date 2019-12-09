
#include <falcontls/bio.h>

#include "tls_locl.h"
#include "tls1.h"
#include "handshake.h"
#include "cipher.h"

void
tls_free_digest_list(TLS *s)
{
    FC_BIO_free(s->tls_state.st_handshake_buffer);
    s->tls_state.st_handshake_buffer = NULL;
    FC_EVP_MD_CTX_free(s->tls_state.st_handshake_dgst);
    s->tls_state.st_handshake_dgst = NULL;  
}

int
tls_init_finished_mac(TLS *s)
{
    FC_BIO  *buf = FC_BIO_new(FC_BIO_s_mem());

    if (buf == NULL) {
        return 0;
    }
    tls_free_digest_list(s);
    s->tls_state.st_handshake_buffer = buf;
    (void)FC_BIO_set_close(s->tls_state.st_handshake_buffer, FC_BIO_CLOSE);
    return 1;
}

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

        s->tls_state.st_handshake_dgst = FC_EVP_MD_CTX_new();
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

