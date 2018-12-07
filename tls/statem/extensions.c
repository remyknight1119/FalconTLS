
#include <falcontls/types.h>
#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "statem_locl.h"
#include "packet_locl.h"

typedef struct extensions_definition_t {
    uint32_t    ed_type;
    uint32_t    ed_context;
    int         (*ed_init)(TLS *s, uint32_t context);
    int         (*ed_parse_ctos)(TLS *s, PACKET *pkt, uint32_t context, X509 *x,
                    size_t chainidx);
    int         (*ed_parse_stoc)(TLS *s, PACKET *pkt, uint32_t context, X509 *x,
                    size_t chainidx);
    EXT_RETURN  (*ed_construct_ctos)(TLS *s, WPACKET *pkt, uint32_t context,
                    X509 *x, size_t chainidx);
    EXT_RETURN  (*ed_construct_stoc)(TLS *s, WPACKET *pkt, uint32_t context,
                    X509 *x, size_t chainidx);
    int         (*ed_final)(TLS *s, uint32_t context, int sent);
} EXTENSION_DEFINITION;


static const EXTENSION_DEFINITION ext_defs[] = {
    {
        .ed_type = TLSEXT_TYPE_encrypt_then_mac,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_2_SERVER_HELLO
            | FC_TLS_EXT_TLS1_2_AND_BELOW_ONLY,
        .ed_init = init_etm,
        .ed_parse_ctos = tls_parse_ctos_etm,
        .ed_parse_stoc = tls_parse_stoc_etm,
        .ed_construct_ctos = tls_construct_stoc_etm,
        .ed_construct_stoc = tls_construct_ctos_etm,
    },
};

