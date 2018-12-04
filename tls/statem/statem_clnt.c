#include <falcontls/types.h>
#include <fc_lib.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"
#include "handshake.h"

static int fctls12_statem_client_read_transition(TLS *s);
static MSG_PROCESS_RETURN fctls12_statem_client_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE fctls12_statem_client_post_process_message(TLS *s);

TLS_READ_STATEM tls12_client_read_statem_proc = {
    .rs_transition = fctls12_statem_client_read_transition,
    .rs_process_message = fctls12_statem_client_process_message,
    .rs_post_process_message = fctls12_statem_client_post_process_message,
};

static int tls_construct_client_hello(TLS *s, WPACKET *pkt);

static TLS_CONSTRUCT_MESSAGE tls12_client_construct_message[] = {
    {
        .cm_hand_state = TLS_ST_CW_CLNT_HELLO,
        .cm_message_type = TLS_MT_CLIENT_HELLO,
        .cm_construct = tls_construct_client_hello,
    },
};

#define tls12_client_construct_message_num \
    FC_ARRAY_SIZE(tls12_client_construct_message)

static WRITE_TRAN fctls12_statem_client_write_transition(TLS *s);
static WORK_STATE fctls12_statem_client_write_pre_work(TLS *s);
static WORK_STATE fctls12_statem_client_write_post_work(TLS *s);
static int fctls12_statem_get_client_construct_message(TLS *s,
        construct_message_f *func, int *m_type);

TLS_WRITE_STATEM tls12_client_write_statem_proc = {
    .ws_transition = fctls12_statem_client_write_transition,
    .ws_pre_work = fctls12_statem_client_write_pre_work,
    .ws_post_work = fctls12_statem_client_write_post_work,
    .ws_get_construct_message = fctls12_statem_get_client_construct_message,
};

static int
fctls12_statem_client_read_transition(TLS *s)
{
    return 1;
}

static MSG_PROCESS_RETURN
fctls12_statem_client_process_message(TLS *s, PACKET *pkt)
{
    return MSG_PROCESS_CONTINUE_READING;
}

static WORK_STATE
fctls12_statem_client_post_process_message(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static WRITE_TRAN
fctls12_statem_client_write_transition(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        case TLS_ST_BEFORE:
            st->sm_hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;
        default:
            return WRITE_TRAN_ERROR;
    }
}

static WORK_STATE
fctls12_statem_client_write_pre_work(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            break;
        default:
            break;
    }

    return WORK_FINISHED_CONTINUE;
}

static WORK_STATE
fctls12_statem_client_write_post_work(TLS *s)
{
    FC_LOG("in\n");
    return WORK_FINISHED_CONTINUE;
}

static int
fctls12_statem_get_client_construct_message(TLS *s, construct_message_f *func,
                int *m_type)
{
    FC_LOG("in\n");

    return tls_stream_get_construct_message(s, func, m_type,
            tls12_client_construct_message,
            tls12_client_construct_message_num);
}

static int
tls_cipher_list_to_bytes(TLS *s, FC_STACK_OF(TLS_CIPHER) *sk, uint8_t *p)
{
    const TLS_CIPHER    *c = NULL;
    uint8_t             *q = NULL;
    int                 i = 0;
    int                 j = 0;
    /* Set disabled masks for this session */
    //ssl_set_client_disabled(s);

    if (sk == NULL) {
        return 0;
    }

    q = p;

    for (i = 0; i < sk_TLS_CIPHER_num(sk); i++) {
        c = sk_TLS_CIPHER_value(sk, i);
        j = s->tls_method->md_put_cipher_by_char(c, p);
        p += j;
    }
    /*
     * If p == q, no ciphers; caller indicates an error. Otherwise, add
     * applicable SCSVs.
     */
    if (p != q) {
#if 0
        if (s->mode & TLS_MODE_SEND_FALLBACK_SCSV) {
            static TLS_CIPHER scsv = {
                0, NULL, TLS_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = s->method->put_cipher_by_char(&scsv, p);
            p += j;
        }
#endif
    }

    return (p - q);
}

static int
tls_construct_client_hello(TLS *s, WPACKET *pkt)
{
    client_hello_t  *ch = NULL;
    unsigned char   *p = NULL;
    int             i = 0;
    int             len = 0;

    FC_LOG("in\n");
    ch = (void *)&pkt->wk_buf->bm_data[pkt->wk_curr];
    ch->ch_version = FC_HTONS(s->tls_version);
    
    p = (void *)(ch + 1);

    /* Ciphers supported */
    i = tls_cipher_list_to_bytes(s, FCTLS_get_ciphers(s), &(p[2]));
    if (i == 0) {
        goto err;
    }
#if 0
    /*
     * Some servers hang if client hello > 256 bytes as hack workaround
     * chop number of supported ciphers to keep it well below this if we
     * use TLS v1.2
     */
    if (TLS1_get_version(s) >= TLS1_2_VERSION
        && i > OPENTLS_MAX_TLS1_2_CIPHER_LENGTH)
        i = OPENTLS_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
    s2n(i, p);
    p += i;

    *(p++) = 1;
    *(p++) = 0;                 /* Add the NULL method */

#if 0
    /* TLS extensions */
    if (ssl_prepare_clienthello_tlsext(s) <= 0) {
        goto err;
    }
    if ((p =
         ssl_add_clienthello_tlsext(s, p, buf + TLS_RT_MAX_PLAIN_LENGTH,
                                    &al)) == NULL) {
        tls_send_alert(s, TLS_AL_FATAL, al);
        goto err;
    }
#endif

    len = p - (unsigned char *)ch;
    pkt->wk_written = len;

    return 1;
err:
    return 0;
}

