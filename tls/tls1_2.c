#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"

TLS_ENC_METHOD const TLSv1_2_enc_data = {
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
    size_t written = 0;
    ret = ssl3_write_bytes(s, type, &s->init_buf->data[s->init_off],
            s->init_num, &written);
    FC_LOG("in\n");

    s->init_off += written;
    s->init_num -= written;
    return 0;
}
