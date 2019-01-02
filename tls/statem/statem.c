
#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"
#include "handshake.h"

/* Sub state machine return values */
typedef enum {
    /* Something bad happened or NBIO */
    SUB_STATE_ERROR,
    /* Sub state finished go to the next sub state */
    SUB_STATE_FINISHED,
    /* Sub state finished and handshake was completed */
    SUB_STATE_END_HANDSHAKE
} SUB_STATE_RETURN;

void 
tls_statem_clear(TLS *s)
{
    s->tls_statem.sm_state = MSG_FLOW_UNINITED;
    s->tls_statem.sm_hand_state = TLS_ST_BEFORE;
    s->tls_statem.sm_in_init = 1;
}

static int
statem_do_write(TLS *s)
{
    return s->tls_method->md_tls_enc->em_do_write(s);
}

static void
init_read_state_machine(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    st->sm_read_state = READ_STATE_HEADER;
}

static void
init_write_state_machine(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    st->sm_write_state = WRITE_STATE_TRANSITION;
}

static SUB_STATE_RETURN
read_state_machine(TLS *s, TLS_READ_STATEM *read)
{
    TLS_STATEM          *st = &s->tls_statem;
    PACKET              pkt = {};
    size_t              len = 0;
    int                 mt = 0;
    int                 ret = 0;

    while (1) {
        switch (st->sm_read_state) {
        case READ_STATE_HEADER:
            FC_LOG("header!\n");
            ret = tls_get_message_header(s, &mt);
            if (ret == 0) {
                return SUB_STATE_ERROR;
            }

            if (!read->rs_transition(s, mt)) {
                return SUB_STATE_ERROR;
            }

            st->sm_read_state = READ_STATE_BODY;
            /* Fall through */

        case READ_STATE_BODY:
            FC_LOG("body!\n");
            ret = tls_get_message_body(s, &len);
            if (ret == 0) {
                FC_LOG("Get message body failed!\n");
                return SUB_STATE_ERROR;
            }

            if (!PACKET_buf_init(&pkt, s->tls_init_msg, len)) {
                return SUB_STATE_ERROR;
            }
            ret = read->rs_process_message(s, &pkt);

            /* Discard the packet data */
            s->tls_init_num = 0;

            switch (ret) {
                case MSG_PROCESS_ERROR:
                    return SUB_STATE_ERROR;

                case MSG_PROCESS_FINISHED_READING:
                    return SUB_STATE_FINISHED;

                case MSG_PROCESS_CONTINUE_PROCESSING:
                    st->sm_read_state = READ_STATE_POST_PROCESS;
                    st->sm_read_state_work = WORK_MORE_A;
                    break;

                default:
                    st->sm_read_state = READ_STATE_HEADER;
                    break;
            }
            break;
        case READ_STATE_POST_PROCESS:
            st->sm_read_state_work = read->rs_post_process_message(s,
                    st->sm_read_state_work);
            switch (st->sm_read_state_work) {
                case WORK_ERROR:
                    break;
                case WORK_MORE_A:
                case WORK_MORE_B:
                    return SUB_STATE_ERROR;
                case WORK_FINISHED_CONTINUE:
                    st->sm_read_state = READ_STATE_HEADER;
                    break;
                case WORK_FINISHED_STOP:
                    return SUB_STATE_FINISHED;
            }
            break;
        default:
            return SUB_STATE_ERROR;
        }
    }
}

static SUB_STATE_RETURN
write_state_machine(TLS *s, TLS_WRITE_STATEM *write)
{
    TLS_STATEM              *st = &s->tls_statem;
    construct_message_f     confunc = NULL;
    WPACKET                 pkt = {};
    int                     mt = 0;
    int                     ret = 0;

    while (1) {
        switch (st->sm_write_state) {
            case WRITE_STATE_TRANSITION:
                switch (write->ws_transition(s)) {
                    case WRITE_TRAN_CONTINUE:
                        st->sm_write_state = WRITE_STATE_PRE_WORK;
                        st->sm_write_state_work = WORK_MORE_A;
                        break;

                    case WRITE_TRAN_FINISHED:
                        return SUB_STATE_FINISHED;

                    case WRITE_TRAN_ERROR:
                        return SUB_STATE_ERROR;
                }
                break;
            case WRITE_STATE_PRE_WORK:
                switch (st->sm_write_state_work = 
                        write->ws_pre_work(s)) {
                    case WORK_ERROR:
                        /* Fall through */
                    case WORK_MORE_A:
                    case WORK_MORE_B:
                        return SUB_STATE_ERROR;

                    case WORK_FINISHED_CONTINUE:
                        st->sm_write_state = WRITE_STATE_SEND;
                        break;

                    case WORK_FINISHED_STOP:
                        return SUB_STATE_END_HANDSHAKE;
                }

                if (write->ws_get_construct_message(s, &confunc,
                            &mt) < 0) {
                    return SUB_STATE_ERROR;
                }

                if (WPACKET_init(&pkt, s->tls_init_buf,
                            tls_hm_header_len(s)) == 0) {
                    return SUB_STATE_ERROR;
                }

                if (confunc != NULL && confunc(s, &pkt) == 0) {
                    return SUB_STATE_ERROR;
                }

                tls_set_handshake_header(s, &pkt, mt);

            case WRITE_STATE_SEND:
                ret = statem_do_write(s);
                if (ret <= 0) {
                    FC_LOG("State error!\n");
                    return SUB_STATE_ERROR;
                }
                st->sm_write_state = WRITE_STATE_POST_WORK;
                st->sm_write_state_work = WORK_MORE_A;
            case WRITE_STATE_POST_WORK:
                switch (st->sm_write_state_work = write->ws_post_work(s)) {
                    case WORK_ERROR:
                        /* Fall through */
                    case WORK_MORE_A:
                    case WORK_MORE_B:
                        FC_LOG("State error!\n");
                        return SUB_STATE_ERROR;

                    case WORK_FINISHED_CONTINUE:
                        st->sm_write_state = WRITE_STATE_TRANSITION;
                        break;

                    case WORK_FINISHED_STOP:
                        return SUB_STATE_END_HANDSHAKE;
                }

                break;
            default:
                return SUB_STATE_ERROR;
        }
    }
}

static int
tls_state_machine(TLS *s, int server, TLS_READ_STATEM *read,
        TLS_WRITE_STATEM *write)
{
    TLS_STATEM  *st = &s->tls_statem;
    FC_BUF_MEM  *buf = NULL;
    int         ssret = 0;
    int         ret = 0;

    st->sm_in_handshake++;
    if (st->sm_state == MSG_FLOW_UNINITED || 
            st->sm_state == MSG_FLOW_RENEGOTIATE) {
        if (st->sm_state == MSG_FLOW_UNINITED) {
            st->sm_hand_state = TLS_ST_BEFORE;
        }
        s->tls_server = server;
        if (s->tls_init_buf == NULL) {
            if ((buf = FC_BUF_MEM_new()) == NULL) {
                FC_LOG("New mem buf failed!\n");
                goto end;
            }
            if (!FC_BUF_MEM_grow(buf, FC_TLS_RT_MAX_PLAIN_LENGTH)) {
                FC_LOG("Grow mem buf failed!\n");
                goto end;
            }
            s->tls_init_buf = buf;
            buf = NULL;
        }

        if (!tls_setup_buffers(s)) {
            FC_LOG("setup buffers failed!\n");
            goto end;
        }

//        s->tls_init_num = 0;
        st->sm_state = MSG_FLOW_WRITING;
        init_write_state_machine(s);
    }

    while (st->sm_state != MSG_FLOW_FINISHED) {
        if (st->sm_state == MSG_FLOW_READING) {
            ssret = read_state_machine(s, read);
            if (ssret == SUB_STATE_FINISHED) {
                st->sm_state = MSG_FLOW_WRITING;
                init_write_state_machine(s);
            } else {
                FC_LOG("Read error!\n");
                goto end;
            }
        } else if (st->sm_state == MSG_FLOW_WRITING) {
            ssret = write_state_machine(s, write);
            if (ssret == SUB_STATE_FINISHED) {
                st->sm_state = MSG_FLOW_READING;
                init_read_state_machine(s);
            } else if (ssret == SUB_STATE_END_HANDSHAKE) {
                st->sm_state = MSG_FLOW_FINISHED;
            } else {
                FC_LOG("Write error, ret = %d!\n", ssret);
                goto end;
            }
        } else {
            FC_LOG("State error!\n");
            goto end;
        }
    }

    st->sm_state = MSG_FLOW_UNINITED;
  
    ret = 1;
end:
    st->sm_in_handshake--;
    FC_BUF_MEM_free(buf);

    return ret;
}

int
tls12_statem_accept(TLS *s)
{
    return tls_state_machine(s, 1, &tls12_server_read_statem_proc,
            &tls12_server_write_statem_proc);
}

int
tls12_statem_connect(TLS *s)
{
    return tls_state_machine(s, 0, &tls12_client_read_statem_proc,
            &tls12_client_write_statem_proc);
}

int
TLS_in_init(TLS *s)
{
    //return s->tls_statem.sm_in_init;
    return 1;
}


