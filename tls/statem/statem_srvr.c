#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"

static int fctls12_statem_server_read_transition(TLS *s, int mt);
static MSG_PROCESS_RETURN fctls12_statem_server_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE fctls12_statem_server_post_process_message(TLS *s);

TLS_READ_STATEM tls12_server_read_statem_proc = {
    .rs_transition = fctls12_statem_server_read_transition,
    .rs_process_message = fctls12_statem_server_process_message,
    .rs_post_process_message = fctls12_statem_server_post_process_message,
};


static WRITE_TRAN fctls12_statem_server_write_transition(TLS *s);
static WORK_STATE fctls12_statem_server_write_pre_work(TLS *s);
static WORK_STATE fctls12_statem_server_write_post_work(TLS *s);
static int fctls12_statem_server_construct_message(TLS *s,
            construct_message_f *func, int *m_type);

TLS_WRITE_STATEM tls12_server_write_statem_proc = {
    .ws_transition = fctls12_statem_server_write_transition,
    .ws_pre_work = fctls12_statem_server_write_pre_work,
    .ws_post_work = fctls12_statem_server_write_post_work,
    .ws_get_construct_message = fctls12_statem_server_construct_message,
};

static int
fctls12_statem_server_read_transition(TLS *s, int mt)
{
    return 1;
}

static MSG_PROCESS_RETURN
fctls12_statem_server_process_message(TLS *s, PACKET *pkt)
{
    return MSG_PROCESS_CONTINUE_READING;
}

static WORK_STATE
fctls12_statem_server_post_process_message(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static WRITE_TRAN
fctls12_statem_server_write_transition(TLS *s)
{
    return WRITE_TRAN_FINISHED;
}

static WORK_STATE
fctls12_statem_server_write_pre_work(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static WORK_STATE
fctls12_statem_server_write_post_work(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static int
fctls12_statem_server_construct_message(TLS *s, construct_message_f *func,
                int *m_type)
{
    return 1;
}

