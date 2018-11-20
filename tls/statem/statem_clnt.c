#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"

static int fctls12_statem_client_read_transition(TLS *s);
static MSG_PROCESS_RETURN fctls12_statem_client_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE fctls12_statem_client_post_process_message(TLS *s);

TLS_READ_STATEM tls12_client_read_statem_proc = {
    .rs_transition = fctls12_statem_client_read_transition,
    .rs_process_message = fctls12_statem_client_process_message,
    .rs_post_process_message = fctls12_statem_client_post_process_message,
};


static WRITE_TRAN fctls12_statem_client_write_transition(TLS *s);
static WORK_STATE fctls12_statem_client_write_pre_work(TLS *s);
static WORK_STATE fctls12_statem_client_write_post_work(TLS *s);
static int fctls12_statem_client_construct_message(TLS *s, WPACKET *pkt);

TLS_WRITE_STATEM tls12_client_write_statem_proc = {
    .ws_transition = fctls12_statem_client_write_transition,
    .ws_pre_work = fctls12_statem_client_write_pre_work,
    .ws_post_work = fctls12_statem_client_write_post_work,
    .ws_construct_message = fctls12_statem_client_construct_message,
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
fctls12_statem_client_construct_message(TLS *s, WPACKET *pkt)
{
    FC_LOG("in\n");
    return 1;
}

