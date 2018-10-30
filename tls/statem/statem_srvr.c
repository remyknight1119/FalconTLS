#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"

static int ftls12_statem_server_read_transition(TLS *s);
static MSG_PROCESS_RETURN ftls12_statem_server_process_message(TLS *s,
                            PACKET *pkt);
static WORK_STATE ftls12_statem_server_post_process_message(TLS *s);

TLS_READ_STATEM tls12_server_read_statem_proc = {
    .rs_transition = ftls12_statem_server_read_transition,
    .rs_process_message = ftls12_statem_server_process_message,
    .rs_post_process_message = ftls12_statem_server_post_process_message,
};


static WRITE_TRAN ftls12_statem_server_write_transition(TLS *s);
static WORK_STATE ftls12_statem_server_write_pre_work(TLS *s);
static WORK_STATE ftls12_statem_server_write_post_work(TLS *s);
static int ftls12_statem_server_construct_message(TLS *s, WPACKET *pkt);

TLS_WRITE_STATEM tls12_server_write_statem_proc = {
    .ws_transition = ftls12_statem_server_write_transition,
    .ws_pre_work = ftls12_statem_server_write_pre_work,
    .ws_post_work = ftls12_statem_server_write_post_work,
    .ws_construct_message = ftls12_statem_server_construct_message,
};

static int
ftls12_statem_server_read_transition(TLS *s)
{
    return 1;
}

static MSG_PROCESS_RETURN
ftls12_statem_server_process_message(TLS *s, PACKET *pkt)
{
    return MSG_PROCESS_CONTINUE_READING;
}

static WORK_STATE
ftls12_statem_server_post_process_message(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static WRITE_TRAN
ftls12_statem_server_write_transition(TLS *s)
{
    return WRITE_TRAN_FINISHED;
}

static WORK_STATE
ftls12_statem_server_write_pre_work(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static WORK_STATE
ftls12_statem_server_write_post_work(TLS *s)
{
    return WORK_FINISHED_CONTINUE;
}

static int
ftls12_statem_server_construct_message(TLS *s, WPACKET *pkt)
{
    return 1;
}

