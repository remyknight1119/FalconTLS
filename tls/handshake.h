#ifndef __FC_TLS_HANDSHAKE_H__
#define __FC_TLS_HANDSHAKE_H__

#include "tls_locl.h"

#define RANDOM_BYTE_LEN         28
#define TLS_HM_HEADER_LENGTH    sizeof(handshake_t)

typedef struct _handshake_t {
    uint8_t         hk_type;
    uint8_t         hk_len[3];
} handshake_t;

typedef struct _random_t {
    uint32_t        rm_unixt_time;
    uint8_t         rm_random_bytes[RANDOM_BYTE_LEN];
} random_t;

typedef struct _extension_t {
    uint16_t        et_type;
    uint16_t        et_length;
} extension_t;

struct _client_hello_t {
    uint16_t        ch_version;
    random_t        ch_random;
    uint8_t         ch_session_id_len;
    uint8_t         ch_session_id[0];
} __attribute__ ((__packed__));

typedef struct _client_hello_t client_hello_t;

struct _server_hello_t {
    uint16_t        sh_version;
    random_t        sh_random;
    uint8_t         sh_session_id_len;
    uint8_t         sh_session_id[0];
} __attribute__ ((__packed__));

typedef struct _server_hello_t server_hello_t;


#define tls_set_handshake_header(s, pkt, mt) \
        s->tls_method->md_tls_enc->em_set_handshake_header(s, pkt, mt)
#define tls_hm_header_len(s) s->tls_method->md_tls_enc->em_hhlen


#endif
