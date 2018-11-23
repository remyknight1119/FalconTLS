#ifndef __FC_STATEM_H__
#define __FC_STATEM_H__

#include <stdbool.h>

#include <falcontls/tls.h>
#include "packet_locl.h"

/* Message processing return codes */
typedef enum {
    /* Something bad happened */
    MSG_PROCESS_ERROR,
    /* We've finished reading - swap to writing */
    MSG_PROCESS_FINISHED_READING,
    /*
     * We've completed the main processing of this message but there is some
     * post processing to be done.
     */
    MSG_PROCESS_CONTINUE_PROCESSING,
    /* We've finished this message - read the next message */
    MSG_PROCESS_CONTINUE_READING
} MSG_PROCESS_RETURN;

typedef enum {
    TLS_ST_BEFORE,
    TLS_ST_OK,
    DTLS_ST_CR_HELLO_VERIFY_REQUEST,
    TLS_ST_CR_SRVR_HELLO,
    TLS_ST_CR_CERT,
    TLS_ST_CR_CERT_STATUS,
    TLS_ST_CR_KEY_EXCH,
    TLS_ST_CR_CERT_REQ,
    TLS_ST_CR_SRVR_DONE,
    TLS_ST_CR_SESSION_TICKET,
    TLS_ST_CR_CHANGE,
    TLS_ST_CR_FINISHED,
    TLS_ST_CW_CLNT_HELLO,
    TLS_ST_CW_CERT,
    TLS_ST_CW_KEY_EXCH,
    TLS_ST_CW_CERT_VRFY,
    TLS_ST_CW_CHANGE,
    TLS_ST_CW_NEXT_PROTO,
    TLS_ST_CW_FINISHED,
    TLS_ST_SW_HELLO_REQ,
    TLS_ST_SR_CLNT_HELLO,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST,
    TLS_ST_SW_SRVR_HELLO,
    TLS_ST_SW_CERT,
    TLS_ST_SW_KEY_EXCH,
    TLS_ST_SW_CERT_REQ,
    TLS_ST_SW_SRVR_DONE,
    TLS_ST_SR_CERT,
    TLS_ST_SR_KEY_EXCH,
    TLS_ST_SR_CERT_VRFY,
    TLS_ST_SR_NEXT_PROTO,
    TLS_ST_SR_CHANGE,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SESSION_TICKET,
    TLS_ST_SW_CERT_STATUS,
    TLS_ST_SW_CHANGE,
    TLS_ST_SW_FINISHED,
    TLS_ST_SW_MAX
} TLS_HANDSHAKE_STATE;

typedef enum {
    /* No handshake in progress */
    MSG_FLOW_UNINITED,
    /* A permanent error with this connection */
    MSG_FLOW_ERROR,
    /* We are about to renegotiate */
    MSG_FLOW_RENEGOTIATE,
    /* We are reading messages */
    MSG_FLOW_READING,
    /* We are writing messages */
    MSG_FLOW_WRITING,
    /* Handshake has finished */
    MSG_FLOW_FINISHED
} MSG_FLOW_STATE;

/*
 * Valid return codes used for functions performing work prior to or after
 * sending or receiving a message
 */
typedef enum {
    /* Something went wrong */
    WORK_ERROR,
    /* We're done working and there shouldn't be anything else to do after */
    WORK_FINISHED_STOP,
    /* We're done working move onto the next thing */
    WORK_FINISHED_CONTINUE,
    /* We're working on phase A */
    WORK_MORE_A,
    /* We're working on phase B */
    WORK_MORE_B
} WORK_STATE;

/* Write transition return codes */
typedef enum {
    /* Something went wrong */
    WRITE_TRAN_ERROR,
    /* A transition was successfully completed and we should continue */
    WRITE_TRAN_CONTINUE,
    /* There is no more write work to be done */
    WRITE_TRAN_FINISHED
} WRITE_TRAN;

/* Read states */
typedef enum {
    READ_STATE_HEADER,
    READ_STATE_BODY,
    READ_STATE_POST_PROCESS
} READ_STATE;

/* Write states */
typedef enum {
    WRITE_STATE_TRANSITION,
    WRITE_STATE_PRE_WORK,
    WRITE_STATE_SEND,
    WRITE_STATE_POST_WORK
} WRITE_STATE;


typedef struct tls_statem_t {
    MSG_FLOW_STATE      sm_state;
    WRITE_STATE         sm_write_state;
    WORK_STATE          sm_write_state_work;
    READ_STATE          sm_read_state;
    WORK_STATE          sm_read_state_work;
    TLS_HANDSHAKE_STATE sm_hand_state;
    bool                sm_in_init;
    int                 sm_in_handshake;
} TLS_STATEM;

typedef struct tls_read_statem_t {
    int                 (*rs_transition)(TLS *s);
    MSG_PROCESS_RETURN  (*rs_process_message)(TLS *s, PACKET *pkt);
    WORK_STATE          (*rs_post_process_message)(TLS *s);
} TLS_READ_STATEM;

typedef struct tls_write_statem_t {
    WRITE_TRAN      (*ws_transition)(TLS *s);
    WORK_STATE      (*ws_pre_work)(TLS *s);
    WORK_STATE      (*ws_post_work)(TLS *s);
    int             (*ws_construct_message)(TLS *s, WPACKET *pkt);
} TLS_WRITE_STATEM;

TLS_READ_STATEM tls12_client_read_statem_proc;
TLS_WRITE_STATEM tls12_client_write_statem_proc;
TLS_READ_STATEM tls12_server_read_statem_proc;
TLS_WRITE_STATEM tls12_server_write_statem_proc;

void tls_statem_clear(TLS *s);
int tls12_statem_accept(TLS *s);
int tls12_statem_connect(TLS *s);
int TLS_in_init(TLS *s);

#endif