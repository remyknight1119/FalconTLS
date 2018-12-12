
#include <falcontls/types.h>
#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "statem_locl.h"
#include "packet_locl.h"

typedef EXT_RETURN (*EXT_CONSTRUCT_F)(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);

static int init_etm(TLS *s, unsigned int context);

typedef struct extensions_definition_t {
    uint32_t            ed_type;
    uint32_t            ed_context;
    int                 (*ed_init)(TLS *s, uint32_t context);
    int                 (*ed_parse_ctos)(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                            size_t chainidx);
    int                 (*ed_parse_stoc)(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                            size_t chainidx);
    EXT_CONSTRUCT_F     ed_construct_ctos;
    EXT_CONSTRUCT_F     ed_construct_stoc;
    int                 (*ed_final)(TLS *s, uint32_t context, int sent);
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

#define EXTENSION_DEF_SIZE FC_ARRAY_SIZE(ext_defs)

int
tls_construct_extensions(TLS *s, WPACKET *pkt, uint32_t context,
        FC_X509 *x, size_t chainidx)
{
    const EXTENSION_DEFINITION  *thisexd = NULL;
    EXT_CONSTRUCT_F             construct = NULL;
    EXT_RETURN                  ret = 0;
    int                         i = 0;

    for (i = 0, thisexd = ext_defs; i < EXTENSION_DEF_SIZE; i++, thisexd++) {
        construct = s->tls_server ? thisexd->ed_construct_stoc
                                  : thisexd->ed_construct_ctos;
        ret = construct(s, pkt, context, x, chainidx);
        if (ret == EXT_RETURN_FAIL) {
            return 0;
        }
    }

    return 1;
}

static int
init_etm(TLS *s, unsigned int context)
{
    s->tls_ext.use_etm = 0;

    return 1;
}


