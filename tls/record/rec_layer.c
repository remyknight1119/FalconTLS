#include <string.h>
#include <falcontls/tls.h>
#include <falcontls/bio.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"

static int
tls_write_pending(TLS *s)
{
    TLS_BUFFER  *wb = s->tls_rlayer.rl_wbuf; 
    int          wlen = 0;

    if (s->tls_wbio == NULL) {
        return -1;
    }
    
    wlen = FC_BIO_write(s->tls_wbio, TLS_BUFFER_get_buf(wb),
            TLS_BUFFER_get_offset(wb));
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
    TLS_BUFFER  *wb = s->tls_rlayer.rl_wbuf; 
    char        *b = NULL;
    int         tot_len = 0;
    int         offset = 0;
    int         wlen = 0;

    b = (void *)TLS_BUFFER_get_buf(wb);
    offset = TLS_RT_HEADER_LENGTH;
    memcpy(b + offset, buf, len);
    tls_set_record_header(s, b, len, type);
    tot_len = len + offset;
    TLS_BUFFER_add_offset(wb, tot_len);
    wlen = tls_write_pending(s);
    if (wlen < 0) {
        return -1;
    }

    *written = (size_t)len;
    FC_LOG("wlen = %d\n", wlen);
    return 0;
}
