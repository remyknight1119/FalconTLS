#include <falcontls/tls.h>
#include <falcontls/bio.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"

static int
tls_write_pending(TLS *s, int type, const void *buf, size_t len)
{
    int     wlen = 0;

    if (s->tls_wbio == NULL) {
        return -1;
    }
    
    wlen = FC_BIO_write(s->tls_wbio, buf, (int)len);
    if (wlen < 0) {
        return -1;
    }

    FC_LOG("wlen = %d\n", wlen);
    return 0;
}

int
tls_write_bytes(TLS *s, int type, const void *buf, size_t len,
        size_t *written)
{
    int     wlen = 0;

    wlen = tls_write_pending(s, type, buf, len);
    if (wlen < 0) {
        return -1;
    }

    *written = (size_t)len;
    FC_LOG("wlen = %d\n", wlen);
    return 0;
}
