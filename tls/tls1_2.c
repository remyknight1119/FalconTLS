#include <falcontls/tls.h>
#include <falcontls/tls1_2.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "record.h"
#include "handshake.h"

static int tls1_2_set_handshake_header(TLS *s, WPACKET *pkt, int mt);

TLS_ENC_METHOD const TLSv1_2_enc_data = {
    .em_set_handshake_header = tls1_2_set_handshake_header,
    .em_hhlen = TLS_HM_HEADER_LENGTH,
    .em_do_write = tls1_2_handshake_write,
};

int 
tls1_2_new(TLS *s)
{
    return 1;
}

void
tls1_2_clear(TLS *s)
{
}

void
tls1_2_free(TLS *s)
{
}

int
tls1_2_accept(TLS *s)
{
    return 1;
}

int
tls1_2_connect(TLS *s)
{
    return 1;
}

int
tls1_2_read(TLS *s, void *buf, int len)
{
    return 1;
}

int
tls1_2_peek(TLS *s, void *buf, int len)
{
    return 1;
}

int
tls1_2_handshake_write(TLS *s)
{
    return tls_do_write(s, TLS1_2_RT_HANDSHAKE);
}

int
tls1_2_set_handshake_header(TLS *s, WPACKET *pkt, int mt)
{
    handshake_t     *h = NULL;
    uint8_t         *len = NULL;

    h = (void *)pkt->wk_buf->bm_data;
    h->hk_type  = mt;
    len = &h->hk_len[0];
    l2n3(pkt->wk_written, len);

    s->tls_init_num = (int)pkt->wk_written + TLS_HM_HEADER_LENGTH;
    s->tls_init_off = 0;

    return 1;
}


