#include <falcontls/tls.h>
#include <internal/buffer.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "record.h"
#include "handshake.h"

int
tls_do_write(TLS *s, int type)
{
    size_t  written = 0;
    int     ret = 0;

    ret = tls_write_bytes(s, type, &s->tls_init_buf->bm_data[s->tls_init_off],
            s->tls_init_num, &written);
    if (ret < 0) {
        return -1;
    }

    if (written == s->tls_init_num) {
        return 1;
    }

    s->tls_init_off += written;
    s->tls_init_num -= written;
    return 0;
}

int
tls_stream_get_construct_message(TLS *s, construct_message_f *func, int *m_type,
        TLS_CONSTRUCT_MESSAGE *array, size_t size)
{
    TLS_STATEM  *st = &s->tls_statem;
    int         i = 0;

    for (i = 0; i < size; i++) {
        if (st->sm_hand_state == array[i].cm_hand_state) {
            *func = array[i].cm_construct;
            *m_type = array[i].cm_message_type;
            return 0;
        }
    }

    return -1;
}

int
tls_get_message_header(TLS *s, int *mt)
{
    unsigned char   *p = NULL;
    //size_t          l = 0;
    size_t          readbytes = 0;
    int             recvd_type = 0;
    int             i = 0;

    p = (unsigned char *)s->tls_init_buf->bm_data;
    do {
        while (s->tls_init_num < TLS_HM_HEADER_LENGTH) {
            i = tls_read_bytes(s, TLS_RT_HANDSHAKE, &recvd_type,
                                          &p[s->tls_init_num],
                                          TLS_HM_HEADER_LENGTH - s->tls_init_num,
                                          &readbytes);
            if (i <= 0) {
                //s->tls_rwstate = SSL_READING;
                return 0;
            }
            if (recvd_type == TLS_RT_CHANGE_CIPHER_SPEC) {
            } else if (recvd_type != TLS_RT_HANDSHAKE) {
                return 0;
            }

            s->tls_init_num += readbytes;
        }
    } while (1);
 
    s->tls_init_msg = s->tls_init_buf->bm_data + TLS_HM_HEADER_LENGTH;
    s->tls_init_num = 0;

    return 1;
}

