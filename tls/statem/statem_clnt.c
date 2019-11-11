#include <falcontls/types.h>
#include <falcontls/x509.h>
#include <fc_lib.h>
#include <fc_log.h>

#include "statem.h"
#include "statem_locl.h"
#include "tls_locl.h"
#include "cipher.h"
#include "handshake.h"

static int fctls_statem_client_read_transition(TLS *s, int mt);
static MSG_PROCESS_RETURN fctls_statem_client_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE fctls_statem_client_post_process_message(TLS *s,
                            WORK_STATE wst);
static int fctls12_statem_client_read_transition(TLS *s, int mt);
static MSG_PROCESS_RETURN fctls12_statem_client_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE fctls12_statem_client_post_process_message(TLS *s,
                            WORK_STATE wst);
static int fctls13_statem_client_read_transition(TLS *s, int mt);
static MSG_PROCESS_RETURN fctls13_statem_client_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE fctls13_statem_client_post_process_message(TLS *s,
                            WORK_STATE wst);

TLS_READ_STATEM tls_client_read_statem_proc = {
    .rs_transition = fctls_statem_client_read_transition,
    .rs_process_message = fctls_statem_client_process_message,
    .rs_post_process_message = fctls_statem_client_post_process_message,
};

TLS_READ_STATEM tls12_client_read_statem_proc = {
    .rs_transition = fctls12_statem_client_read_transition,
    .rs_process_message = fctls12_statem_client_process_message,
    .rs_post_process_message = fctls12_statem_client_post_process_message,
};

TLS_READ_STATEM tls13_client_read_statem_proc = {
    .rs_transition = fctls13_statem_client_read_transition,
    .rs_process_message = fctls13_statem_client_process_message,
    .rs_post_process_message = fctls13_statem_client_post_process_message,
};

static int tls_construct_client_hello(TLS *s, WPACKET *pkt);
static int tls1_2_construct_client_certificate(TLS *s, WPACKET *pkt);
//static int tls1_3_construct_client_certificate(TLS *s, WPACKET *pkt);

static TLS_CONSTRUCT_MESSAGE tls_client_construct_message[] = {
    {
        .cm_hand_state = TLS_ST_CW_CLNT_HELLO,
        .cm_message_type = TLS_MT_CLIENT_HELLO,
        .cm_construct = tls_construct_client_hello,
    },
    {
        .cm_hand_state = TLS_ST_CW_CERT,
        .cm_message_type = TLS_MT_CERTIFICATE,
        .cm_construct = tls1_2_construct_client_certificate,
    },
};

static TLS_CONSTRUCT_MESSAGE tls12_client_construct_message[] = {
    {
        .cm_hand_state = TLS_ST_CW_CLNT_HELLO,
        .cm_message_type = TLS_MT_CLIENT_HELLO,
        .cm_construct = tls_construct_client_hello,
    },
    {
        .cm_hand_state = TLS_ST_CW_CERT,
        .cm_message_type = TLS_MT_CERTIFICATE,
        .cm_construct = tls1_2_construct_client_certificate,
    },
};

static TLS_CONSTRUCT_MESSAGE tls13_client_construct_message[] = {
    {
        .cm_hand_state = TLS_ST_CW_CLNT_HELLO,
        .cm_message_type = TLS_MT_CLIENT_HELLO,
        .cm_construct = tls_construct_client_hello,
    },
#if 0
    {
        .cm_hand_state = TLS_ST_CW_CERT,
        .cm_message_type = TLS_MT_CERTIFICATE,
        .cm_construct = tls1_3_construct_client_certificate,
    },
#endif
};

#define tls_client_construct_message_num \
    FC_ARRAY_SIZE(tls_client_construct_message)
#define tls12_client_construct_message_num \
    FC_ARRAY_SIZE(tls12_client_construct_message)
#define tls13_client_construct_message_num \
    FC_ARRAY_SIZE(tls13_client_construct_message)

static MSG_PROCESS_RETURN tls_process_server_hello(TLS *s, PACKET *pkt);
static MSG_PROCESS_RETURN tls1_2_process_server_certificate(TLS *s,
                            PACKET *pkt);
static MSG_PROCESS_RETURN tls1_2_process_key_exchange(TLS *s, PACKET *pkt);
static MSG_PROCESS_RETURN tls1_2_process_certificate_request(TLS *s,
                            PACKET *pkt);
static MSG_PROCESS_RETURN tls1_2_process_server_done(TLS *s, PACKET *pkt);

static TLS_PROCESS_MESSAGE tls_client_process_message[] = {
    {
        .pm_hand_state = TLS_ST_CR_SRVR_HELLO,
        .pm_proc = tls_process_server_hello,
    },
    {
        .pm_hand_state = TLS_ST_CR_CERT,
        .pm_proc = tls1_2_process_server_certificate,
    },
    {
        .pm_hand_state = TLS_ST_CR_KEY_EXCH,
        .pm_proc = tls1_2_process_key_exchange,
    },
    {
        .pm_hand_state = TLS_ST_CR_CERT_REQ,
        .pm_proc = tls1_2_process_certificate_request,
    },
    {
        .pm_hand_state = TLS_ST_CR_SRVR_DONE,
        .pm_proc = tls1_2_process_server_done,
    },
};

#define tls_client_process_message_num \
    FC_ARRAY_SIZE(tls_client_process_message)

static TLS_PROCESS_MESSAGE tls12_client_process_message[] = {
    {
        .pm_hand_state = TLS_ST_CR_SRVR_HELLO,
        .pm_proc = tls_process_server_hello,
    },
    {
        .pm_hand_state = TLS_ST_CR_CERT,
        .pm_proc = tls1_2_process_server_certificate,
    },
    {
        .pm_hand_state = TLS_ST_CR_KEY_EXCH,
        .pm_proc = tls1_2_process_key_exchange,
    },
    {
        .pm_hand_state = TLS_ST_CR_CERT_REQ,
        .pm_proc = tls1_2_process_certificate_request,
    },
    {
        .pm_hand_state = TLS_ST_CR_SRVR_DONE,
        .pm_proc = tls1_2_process_server_done,
    },
};

#define tls12_client_process_message_num \
    FC_ARRAY_SIZE(tls12_client_process_message)

static TLS_PROCESS_MESSAGE tls13_client_process_message[] = {
    {
        .pm_hand_state = TLS_ST_CR_SRVR_HELLO,
        .pm_proc = tls_process_server_hello,
    },
};

#define tls13_client_process_message_num \
    FC_ARRAY_SIZE(tls13_client_process_message)

static int tls_process_ske_ecdhe(TLS *s, PACKET *pkt, FC_EVP_PKEY **pkey);

TLS_PROCESS_KEY_EXCHANGE tls12_client_process_key_exchange[] = {
    {
        .ke_alg_k = TLS_kECDHE,
        .ke_proc = tls_process_ske_ecdhe,
    },
};

#define tls12_client_process_key_exchange_num \
    FC_ARRAY_SIZE(tls12_client_process_key_exchange)

static int fctls_statem_get_client_construct_message(TLS *s,
        construct_message_f *func, int *m_type);
static WRITE_TRAN fctls12_statem_client_write_transition(TLS *s);
static WORK_STATE fctls12_statem_client_write_pre_work(TLS *s);
static WORK_STATE fctls12_statem_client_write_post_work(TLS *s);
static int fctls12_statem_get_client_construct_message(TLS *s,
        construct_message_f *func, int *m_type);
static WRITE_TRAN fctls13_statem_client_write_transition(TLS *s);
static WORK_STATE fctls13_statem_client_write_pre_work(TLS *s);
static WORK_STATE fctls13_statem_client_write_post_work(TLS *s);
static int fctls13_statem_get_client_construct_message(TLS *s,
        construct_message_f *func, int *m_type);

TLS_WRITE_STATEM tls_client_write_statem_proc = {
    .ws_transition = fctls12_statem_client_write_transition,
    .ws_pre_work = fctls12_statem_client_write_pre_work,
    .ws_post_work = fctls12_statem_client_write_post_work,
    .ws_get_construct_message = fctls_statem_get_client_construct_message,
};

TLS_WRITE_STATEM tls12_client_write_statem_proc = {
    .ws_transition = fctls12_statem_client_write_transition,
    .ws_pre_work = fctls12_statem_client_write_pre_work,
    .ws_post_work = fctls12_statem_client_write_post_work,
    .ws_get_construct_message = fctls12_statem_get_client_construct_message,
};

TLS_WRITE_STATEM tls13_client_write_statem_proc = {
    .ws_transition = fctls13_statem_client_write_transition,
    .ws_pre_work = fctls13_statem_client_write_pre_work,
    .ws_post_work = fctls13_statem_client_write_post_work,
    .ws_get_construct_message = fctls13_statem_get_client_construct_message,
};

static inline int
cert_req_allowed(TLS *s)
{
    /* TLS does not like anon-DH with client cert */
#if 0
    if (s->s3->tmp.new_cipher->algorithm_auth & (TLS_aSRP | TLS_aPSK)) {
        return 0;
    }
#endif

    return 1;
}

static int
fctls_statem_client_read_transition(TLS *s, int mt)
{
    TLS_STATEM  *st = &s->tls_statem;

    FC_LOG("mt = %d\n", mt);
    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            if (mt == TLS_MT_SERVER_HELLO) {
                st->sm_hand_state = TLS_ST_CR_SRVR_HELLO;
                return 1;
            }

            break;
        case TLS_ST_CR_SRVR_HELLO:
            if (mt == TLS_MT_CERTIFICATE) {
                st->sm_hand_state = TLS_ST_CR_CERT;
                return 1;
            }
        case TLS_ST_CR_CERT:
            /* Fall through */

        case TLS_ST_CR_CERT_STATUS:
            if (mt == TLS_MT_SERVER_KEY_EXCHANGE) {
                st->sm_hand_state = TLS_ST_CR_KEY_EXCH;
                return 1;
            }
            /* Fall through */
        case TLS_ST_CR_KEY_EXCH:
            if (mt == TLS_MT_CERTIFICATE_REQUEST) {
                if (cert_req_allowed(s)) {
                    st->sm_hand_state = TLS_ST_CR_CERT_REQ;
                    return 1;
                }
                break;
            }
            /* Fall through */

        case TLS_ST_CR_CERT_REQ:
            if (mt == TLS_MT_SERVER_DONE) {
                st->sm_hand_state = TLS_ST_CR_SRVR_DONE;
                return 1;
            }

            break;
        default:
            break;
    }

    return 0;
}


static int
fctls12_statem_client_read_transition(TLS *s, int mt)
{
    return fctls_statem_client_read_transition(s, mt);
}

static int
fctls13_statem_client_read_transition(TLS *s, int mt)
{
    TLS_STATEM  *st = &s->tls_statem;

    FC_LOG("mt = %d\n", mt);
    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            if (mt == TLS_MT_SERVER_HELLO) {
                st->sm_hand_state = TLS_ST_CR_SRVR_HELLO;
                return 1;
            }
            break;
        default:
            break;
    }

    return 0;
}

static MSG_PROCESS_RETURN
fctls_statem_process_message(TLS *s, PACKET *pkt, TLS_PROCESS_MESSAGE *pm, size_t num)
{
    process_message_f   proc = NULL;

    proc = tls_stream_get_process_message(s, pm, num); 
    if (proc == NULL) {
        return MSG_PROCESS_ERROR; 
    }

    return proc(s, pkt);
}


static MSG_PROCESS_RETURN
fctls_statem_client_process_message(TLS *s, PACKET *pkt)
{
    return fctls_statem_process_message(s, pkt, tls_client_process_message,
            tls_client_process_message_num);
}

static MSG_PROCESS_RETURN
fctls12_statem_client_process_message(TLS *s, PACKET *pkt)
{
    return fctls_statem_process_message(s, pkt, tls12_client_process_message,
            tls12_client_process_message_num);
}

static MSG_PROCESS_RETURN
fctls13_statem_client_process_message(TLS *s, PACKET *pkt)
{
    return fctls_statem_process_message(s, pkt, tls13_client_process_message,
            tls13_client_process_message_num);
}

WORK_STATE
tls_prepare_client_certificate(TLS *s, WORK_STATE wst)
{
    return WORK_FINISHED_CONTINUE;
}

static WORK_STATE
fctls_statem_client_post_process_message(TLS *s, WORK_STATE wst)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        default:
            return WORK_ERROR;
    }
}

static WORK_STATE
fctls12_statem_client_post_process_message(TLS *s, WORK_STATE wst)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        case TLS_ST_CR_CERT_REQ:
            return tls_prepare_client_certificate(s, wst);
        default:
            return WORK_ERROR;
    }
}

static WORK_STATE
fctls13_statem_client_post_process_message(TLS *s, WORK_STATE wst)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        default:
            return WORK_ERROR;
    }
}

static WRITE_TRAN
fctls12_statem_client_write_transition(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;
    TLS_STATE   *t = NULL;

    t = &s->tls_state;
    switch (st->sm_hand_state) {
        case TLS_ST_BEFORE:
            st->sm_hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;
        case TLS_ST_CW_CLNT_HELLO:
            return WRITE_TRAN_FINISHED;
        case TLS_ST_CR_SRVR_DONE:
            st->sm_hand_state = 
                (t->st_cert_req == 1) ? TLS_ST_CW_CERT:TLS_ST_CW_CHANGE;
            return WRITE_TRAN_CONTINUE;
        default:
            return WRITE_TRAN_ERROR;
    }
}

static WRITE_TRAN
fctls13_statem_client_write_transition(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;
#if 0
    TLS_STATE   *t = NULL;

    t = &s->tls_state;
#endif
    switch (st->sm_hand_state) {
        case TLS_ST_BEFORE:
            st->sm_hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;
        case TLS_ST_CW_CLNT_HELLO:
            return WRITE_TRAN_FINISHED;
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
fctls13_statem_client_write_pre_work(TLS *s)
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
    TLS_STATEM  *st = &s->tls_statem;

    FC_LOG("in\n");
    s->tls_init_num = 0;
    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            break;
        default:
            break;
    }

    return WORK_FINISHED_CONTINUE;
}

static WORK_STATE
fctls13_statem_client_write_post_work(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    FC_LOG("in\n");
    s->tls_init_num = 0;
    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            break;
        default:
            break;
    }

    return WORK_FINISHED_CONTINUE;
}

static int
fctls_statem_get_client_construct_message(TLS *s, construct_message_f *func,
                int *m_type)
{
    FC_LOG("in\n");

    return tls_stream_get_construct_message(s, func, m_type,
            tls_client_construct_message,
            tls_client_construct_message_num);
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
fctls13_statem_get_client_construct_message(TLS *s, construct_message_f *func,
                int *m_type)
{
    FC_LOG("in\n");

    return tls_stream_get_construct_message(s, func, m_type,
            tls13_client_construct_message,
            tls13_client_construct_message_num);
}

static int
tls_cipher_list_to_bytes(TLS *s, FC_STACK_OF(TLS_CIPHER) *sk, WPACKET *pkt)
{
    const TLS_CIPHER    *c = NULL;
    size_t              totlen = 0;
    size_t              len = 0;
    int                 i = 0;
    /* Set disabled masks for this session */
    //ssl_set_client_disabled(s);

    if (sk == NULL) {
        return 0;
    }

    for (i = 0; i < sk_TLS_CIPHER_num(sk); i++) {
        c = sk_TLS_CIPHER_value(sk, i);
        if (!s->tls_method->md_put_cipher_by_char(c, pkt, &len)) {
            return 0;
        }
        totlen += len;
    }
    /*
     * If p == q, no ciphers; caller indicates an error. Otherwise, add
     * applicable SCSVs.
     */
    if (totlen != 0) {
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

    return 1;
}

int ssl_set_client_hello_version(TLS *s)
{
    int     ver_min = 0;
    int     ver_max = 0;
    int     ret = 0;

    ret = tls_get_min_max_version(s, &ver_min, &ver_max);
    if (ret != 0) {
        return ret;
    }

    s->tls_version = ver_max;

    /* TLS1.3 always uses TLS1.2 in the legacy_version field */
    if (ver_max > FC_TLS1_2_VERSION) {
        ver_max = FC_TLS1_2_VERSION;
    }

    s->tls_client_version = ver_max;

    return 0;
}

static int
tls_construct_client_hello(TLS *s, WPACKET *pkt)
{
    TLS_RANDOM   *random = NULL;
    TLS_SESSION     *sess = s->tls_session;
    unsigned char   *session_id = NULL;
    size_t          sess_id_len = 0;
    int             protverr = 0;

    FC_LOG("IIIIIIIIIIIIIn\n");
    if (!WPACKET_set_max_size(pkt, FC_TLS_RT_MAX_PLAIN_LENGTH)) {
        FC_LOG("Err\n");
        goto err;
    }
    
    protverr = ssl_set_client_hello_version(s);
    if (protverr != 0) {
        FC_LOG("Set version\n");
        goto err;
    }

    random = &s->tls_state.st_client_random;
    if (!WPACKET_put_bytes_u16(pkt, s->tls_client_version) ||
            !WPACKET_memcpy(pkt, random, sizeof(*random))) {
        FC_LOG("Err\n");
        goto err;
    }

    if (sess == NULL) {
        if (!tls_get_new_session(s, 1)) {
            goto err;
        }
    }

    if (!WPACKET_start_sub_packet_u8(pkt) ||
            (sess_id_len && !WPACKET_memcpy(pkt, session_id, sess_id_len)) ||
            !WPACKET_close(pkt)) {
        goto err;
    }

    if (!WPACKET_start_sub_packet_u16(pkt)) {
        goto err;
    }

    /* Ciphers supported */
    if (!tls_cipher_list_to_bytes(s, FCTLS_get_ciphers(s), pkt)) {
        goto err;
    }

    if (!WPACKET_close(pkt)) {
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

    if (!WPACKET_put_bytes_u8(pkt, 1)
            || !WPACKET_put_bytes_u8(pkt, 0)) {
        FC_LOG("Err\n");
        goto err;
    }

    /* TLS extensions */
    if (tls_construct_extensions(s, pkt, FC_TLS_EXT_CLIENT_HELLO,
                NULL, 0) == 0) {
        //tls_send_alert(s, TLS_AL_FATAL, al);
        FC_LOG("Err\n");
        goto err;
    }

    return 1;
err:
    return 0;
}

static int
tls1_2_construct_client_certificate(TLS *s, WPACKET *pkt)
{
    FC_LOG("IIIIIIIIIIIIIn\n");

    return tls_output_cert_chain(s, pkt, s->tls_cert->ct_key);
}

static int
set_client_ciphersuite(TLS *s, const unsigned char *cipherchars)
{
    FC_STACK_OF(TLS_CIPHER) *sk = NULL;
    const TLS_CIPHER        *c = NULL;
    int                     i = 0;

    c = tls_get_cipher_by_char(s, cipherchars);
    if (c == NULL) {
        FC_LOG("Get cipher failed\n");
        return 0;
    }
 
    sk = tls_get_ciphers_by_id(s);
    i = sk_TLS_CIPHER_find(sk, c);
    if (i < 0) {
        FC_LOG("Find cipher failed, sk = %p\n", sk);
        return 0;
    }

    s->tls_cipher = c;

    return 1;
}

static int
tls_parse_server_hello(TLS *s, PACKET *pkt, SERVERHELLO_MSG *msg)
{
    TLS_RANDOM          *server_random = NULL;
    unsigned int        sversion = 0;

    if (!PACKET_get_net_2(pkt, &sversion)) {
        goto err;
    }

    server_random = &s->tls_state.st_server_random;
    /* load the server random */
    if (!PACKET_copy_bytes(pkt, server_random, sizeof(*server_random))) {
        goto err;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &msg->sm_session_id)) {
        goto err;
    }
 
    if (!PACKET_get_bytes(pkt, &msg->sm_cipherchars, TLS_CIPHER_LEN)) {
        goto err;
    }
 
    if (!PACKET_get_1(pkt, &msg->sm_compression)) {
        goto err;
    }
 
    /* TLS extensions */
    if (PACKET_remaining(pkt) == 0) {
        PACKET_null_init(&msg->sm_extpkt);
    } else if (!PACKET_as_length_prefixed_2(pkt, &msg->sm_extpkt)
               || PACKET_remaining(pkt) != 0) {
        goto err;
    }
 
    //tls_collect_extensions
    if (!tls_collect_extensions(s, &msg->sm_extpkt,
                FC_TLS_EXT_TLS1_2_SERVER_HELLO
                | FC_TLS_EXT_TLS1_3_SERVER_HELLO,
                &msg->sm_extensions, NULL, 1)) {
        goto err;
    }

    if (!tls_choose_client_version(s, sversion, msg->sm_extensions)) {
        FC_LOG("Choose client version failed\n");
        goto err;
    }

    return 1;
err:
    return 0;
}

static MSG_PROCESS_RETURN
tls_process_server_hello(TLS *s, PACKET *pkt)
{
    SERVERHELLO_MSG     msg = {};
    int                 content = 0;

    FC_LOG("in\n");
    if (!tls_parse_server_hello(s, pkt, &msg)) {
        FC_LOG("Parse server_hello failed\n");
        goto err;
    }

    if (!set_client_ciphersuite(s, msg.sm_cipherchars)) {
        FC_LOG("Set client ciphersuite failed\n");
        goto err;
    }

    content = TLS_IS_TLS13(s) ?
        FC_TLS_EXT_TLS1_3_SERVER_HELLO:FC_TLS_EXT_TLS1_2_SERVER_HELLO;
    if (!tls_parse_all_extensions(s, content, msg.sm_extensions, NULL, 0, 1)) {
        FC_LOG("Parse all extensions failed\n");
        goto err;
    }

    if ((!s->method->md_tls_enc->em_setup_key_block(s)
                || !s->method->md_tls_enc->em_change_cipher_state(s,
                    TLS_CC_HANDSHAKE | TLS_CHANGE_CIPHER_CLIENT_READ))) {
        FC_LOG("setup key block failed\n");
        goto err;
    }

    return MSG_PROCESS_CONTINUE_READING;
err:
    return MSG_PROCESS_ERROR;
}

static MSG_PROCESS_RETURN
tls1_2_process_server_certificate(TLS *s,
                            PACKET *pkt)
{
    FC_STACK_OF(FC_X509)    *sk = NULL;
    FC_X509                 *x = NULL;
    FC_EVP_PKEY             *pkey = NULL;
    const unsigned char     *certstart = NULL;
    const unsigned char     *certbytes = NULL;
    unsigned long           cert_list_len = 0;
    unsigned long           cert_len = 0;
    int                     i = 0;
    MSG_PROCESS_RETURN      ret = MSG_PROCESS_ERROR;

    FC_LOG("in\n");
    if ((sk = sk_FC_X509_new_null()) == NULL) {
        goto err;
    }

    if (!PACKET_get_net_3(pkt, &cert_list_len)) {
        goto err;
    }

    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_net_3(pkt, &cert_len) ||
                !PACKET_get_bytes(pkt, &certbytes, cert_len)) {
            goto err;
        }

        certstart = certbytes;

        x = d2i_FC_X509(NULL, &certbytes, cert_len);
        if (x == NULL) {
            FC_LOG("d2i X509 failed\n");
            goto err;
        }
        if (certbytes != (certstart + cert_len)) {
            FC_LOG("certbytes error!\n");
            goto err;
        }

        if (!sk_FC_X509_push(sk, x)) {
            goto err;
        }
        x = NULL;
    }

    i = tls_verify_cert_chain(s, sk);
    if (i != 1) {
        goto err;
    }

    x = sk_FC_X509_value(sk, 0);
    pkey = FC_X509_get0_pubkey(x); 
    if (pkey == NULL) {
        FC_LOG("pkey == NULL\n");
        goto err;
    }
    FC_X509_free(s->tls_session->se_peer);
    FC_X509_up_ref(x);
    s->tls_session->se_peer = x;
    x = NULL;
    ret = MSG_PROCESS_CONTINUE_READING;

err:
    FC_X509_free(x);
    sk_FC_X509_pop_free(sk, FC_X509_free);
    return ret;
}

static int
tls_process_ske_ecdhe(TLS *s, PACKET *pkt, FC_EVP_PKEY **pkey)
{
    PACKET          encoded_pt = {};
    uint64_t        alg_auth = 0;
    unsigned int    curve_type = 0;
    unsigned int    curve_id = 0;

    FC_LOG("in\n");
    /*
     * Extract elliptic curve parameters and the server's ephemeral ECDH
     * public key. We only support named (not generic) curves and
     * ECParameters in this case is just three bytes.
     */
    if (!PACKET_get_1(pkt, &curve_type) || !PACKET_get_net_2(pkt, &curve_id)) {
        return 0;
    }
 
   /*
     * Check curve is named curve type and one of our preferences, if not
     * server has sent an invalid curve.
     */
    if (curve_type != NAMED_CURVE_TYPE
            || !tls1_check_group_id(s, curve_id, 1)) {
        return 0;
    }

    if ((s->tls_peer_key = tls_generate_param_group(curve_id)) == NULL) {
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
        return 0;
    }

    if (!FC_EVP_PKEY_set1_tls_encodedpoint(s->tls_peer_key,
                                        PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        return 0;
    }

    alg_auth = s->tls_cipher->cp_algorithm_auth;
    /*
     * The ECC/TLS specification does not mention the use of DSA to sign
     * ECParameters in the server key exchange message. We do support RSA
     * and ECDSA.
     */
    if (alg_auth & TLS_aECDSA) {
        FC_LOG("ECDSA\n");
        *pkey = FC_X509_get0_pubkey(s->tls_session->se_peer);
    } else if (alg_auth & TLS_aRSA) {
        FC_LOG("RSA\n");
        *pkey = FC_X509_get0_pubkey(s->tls_session->se_peer);
    }
    /* else anonymous ECDH, so no certificate or pkey. */

    FC_LOG("next\n");
    return 1;
}

static MSG_PROCESS_RETURN
tls1_2_process_key_exchange(TLS *s, PACKET *pkt)
{
    FC_EVP_PKEY             *pkey = NULL;
    process_key_exchange_f  proc = NULL;
    PACKET                  save_param_start = {};
    //PACKET                  signature = {};
    PACKET                  params = {};
    uint64_t                alg_k = 0;
    unsigned int            sigalg = 0;

    FC_LOG("in\n");
    save_param_start = *pkt;
    alg_k = s->tls_cipher->cp_algorithm_mkey;
    proc = tls_stream_get_process_key_exchange(alg_k,
            tls12_client_process_key_exchange, 
            tls12_client_process_key_exchange_num);
    if (proc == NULL) {
        goto err;
    }

    if (!proc(s, pkt, &pkey)) {
        goto err;
    }

    if (pkey != NULL) {
        /*
         * |pkt| now points to the beginning of the signature, so the difference
         * equals the length of the parameters.
         */
        if (!PACKET_get_sub_packet(&save_param_start, &params,
                                   PACKET_remaining(&save_param_start) -
                                   PACKET_remaining(pkt))) {
            goto err;
        }

        if (TLS_USE_SIGALGS(s)) {
            if (!PACKET_get_net_2(pkt, &sigalg)) {
                goto err;
            }
 
            if (tls12_check_peer_sigalg(s, sigalg, pkey) <= 0) {
                goto err;
            }
        }

    } else {
    }

    return MSG_PROCESS_CONTINUE_READING;
err:
    return MSG_PROCESS_ERROR;
}

static MSG_PROCESS_RETURN
tls1_2_process_certificate_request(TLS *s, PACKET *pkt)
{
    TLS_STATE   *st = NULL;
    PACKET      ctypes = {};
    PACKET      sigalgs = {};

    st = &s->tls_state;
    memset(&st->st_valid_flags[0], 0, sizeof(st->st_valid_flags));

    /* get the certificate types */
    if (!PACKET_get_length_prefixed_1(pkt, &ctypes)) {
        FC_LOG("error\n");
        return MSG_PROCESS_ERROR;
    }

    if (!PACKET_memdup(&ctypes, &st->st_ctype, &st->st_ctype_len)) {
        FC_LOG("error\n");
        return MSG_PROCESS_ERROR;
    }

    if (TLS_USE_SIGALGS(s)) {
        if (!PACKET_get_length_prefixed_2(pkt, &sigalgs)) {
            FC_LOG("error\n");
            return MSG_PROCESS_ERROR;
        }

        /*
         * Despite this being for certificates, preserve compatibility
         * with pre-TLS 1.3 and use the regular sigalgs field.
         */
        if (!tls1_save_sigalgs(s, &sigalgs, 0)) {
            FC_LOG("error\n");
            return MSG_PROCESS_ERROR;
        }
        if (!tls1_process_sigalgs(s)) {
            FC_LOG("error\n");
            return MSG_PROCESS_ERROR;
        }
    }

    /* get the CA RDNs */
    if (!parse_ca_names(s, pkt)) {
        /* SSLfatal() already called */
        FC_LOG("error\n");
        return MSG_PROCESS_ERROR;
    }

    if (PACKET_remaining(pkt) != 0) {
        FC_LOG("error\n");
        return MSG_PROCESS_ERROR;
    }

    /* we should setup a certificate to return.... */
    st->st_cert_req = 1;

    FC_LOG("OUT!\n");
    return MSG_PROCESS_CONTINUE_PROCESSING;
}

int
tls_process_initial_server_flight(TLS *s)
{
    return 1;
}

static MSG_PROCESS_RETURN
tls1_2_process_server_done(TLS *s, PACKET *pkt)
{
    if (PACKET_remaining(pkt) > 0) {
        return MSG_PROCESS_ERROR;
    }

    if (!tls_process_initial_server_flight(s)) {
        return MSG_PROCESS_ERROR;
    }

    FC_LOG("Server Done\n");
    return MSG_PROCESS_FINISHED_READING;
}


