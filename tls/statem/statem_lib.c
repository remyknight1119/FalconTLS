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

    ret = s->tls_method->md_tls_write_bytes(s, type,
            &s->tls_init_buf->bm_data[s->tls_init_off],
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

process_message_f
tls_stream_get_process_message(TLS *s, TLS_PROCESS_MESSAGE *array, size_t size)
{
    TLS_STATEM  *st = &s->tls_statem;
    int         i = 0;

    for (i = 0; i < size; i++) {
        if (st->sm_hand_state == array[i].pm_hand_state) {
            return array[i].pm_proc;
        }
    }

    return NULL;
}

process_key_exchange_f
tls_stream_get_process_key_exchange(uint64_t alg_k,
            TLS_PROCESS_KEY_EXCHANGE *array,
            size_t size)
{
    int         i = 0;

    for (i = 0; i < size; i++) {
        if (alg_k & array[i].ke_alg_k) {
            return array[i].ke_proc;
        }
    }

    return NULL;
}


int
tls_get_message_header(TLS *s, int *mt)
{
    unsigned char   *p = NULL;
    size_t          l = 0;
    size_t          readbytes = 0;
    int             recvd_type = 0;
    int             skip_message = 0;
    int             i = 0;

    p = (unsigned char *)TLS_GET_INIT_BUF_DATA(s);
    do {
        while (s->tls_init_num < TLS_HM_HEADER_LENGTH) {
            i = s->tls_method->md_tls_read_bytes(s, TLS_RT_HANDSHAKE, &recvd_type,
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
            skip_message = 0;
        }
    } while (skip_message);
 
    *mt = *p;
    s->tls_state.st_message_type = *(p++);
    n2l3(p, l);
    s->tls_state.st_message_size = l;

    s->tls_init_msg = TLS_GET_INIT_BUF_DATA(s) + TLS_HM_HEADER_LENGTH;
    s->tls_init_num = 0;

    return 1;
}

int
tls_get_message_body(TLS *s, size_t *len)
{
    unsigned char   *p = NULL;
    size_t          n = 0;
    size_t          readbytes = 0;
    int             i = 0;

    p = s->tls_init_msg;
    n = s->tls_state.st_message_size - s->tls_init_num;
    FC_LOG("s = %d, num = %d\n", (int)s->tls_state.st_message_size, (int)s->tls_init_num);
    while (n > 0) {
        i = s->tls_method->md_tls_read_bytes(s, TLS_RT_HANDSHAKE, NULL,
                            &p[s->tls_init_num], n, &readbytes);
        if (i <= 0) {
            //s->rwstate = SSL_READING;
            *len = 0;
            return 0;
        }
        s->tls_init_num += readbytes;
        n -= readbytes;
    }

    *len = s->tls_init_num;

    return 1;
}

int
tls_close_construct_packet(TLS *s, WPACKET *pkt, int htype)
{
    size_t      msglen = 0;

    if ((htype != TLS_MT_CHANGE_CIPHER_SPEC && !WPACKET_close(pkt))
            || !WPACKET_get_length(pkt, &msglen)) {
        return 0;
    }

    s->tls_init_num = (int)msglen;
    s->tls_init_off = 0;

    return 1;
}

int
parse_ca_names(TLS *s, PACKET *pkt)
{
    //const unsigned char     *namestart = NULL;
    const unsigned char     *namebytes = NULL;
    unsigned int            name_len = 0;
    PACKET                  cadns = {};

    if (!PACKET_get_length_prefixed_2(pkt, &cadns)) {
        goto err;
    }

    while (PACKET_remaining(&cadns)) {
        if (!PACKET_get_net_2(&cadns, &name_len) ||
            !PACKET_get_bytes(&cadns, &namebytes, name_len)) {
            goto err;
        }
    }

    return 1;
err:
    return 0;
}

int
tls_output_cert_chain(TLS *s, WPACKET *pkt, CERT_PKEY *cpk)
{
    return 1;
}

