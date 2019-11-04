
#include <falcontls/types.h>
#include <falcontls/tls.h>
#include <fc_lib.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "statem_locl.h"
#include "packet_locl.h"

typedef EXT_RETURN (*EXT_CONSTRUCT_F)(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);

static int init_etm(TLS *s, unsigned int context);
static int init_ems(TLS *s, unsigned int context);
static int init_sig_algs(TLS *s, unsigned int context);
static int final_sig_algs(TLS *s, unsigned int context, int sent);
static int final_key_share(TLS *s, unsigned int context, int sent);
static int final_ems(TLS *s, unsigned int context, int sent);
static int final_ec_pt_formats(TLS *s, unsigned int context, int sent);

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
        .ed_type = TLSEXT_TYPE_ec_point_formats,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_2_SERVER_HELLO
            | FC_TLS_EXT_TLS1_2_AND_BELOW_ONLY,
        .ed_parse_ctos = tls_parse_ctos_ec_pt_formats,
        .ed_parse_stoc = tls_parse_stoc_ec_pt_formats,
        .ed_construct_stoc = tls_construct_stoc_ec_pt_formats,
        .ed_construct_ctos = tls_construct_ctos_ec_pt_formats,
        .ed_final = final_ec_pt_formats,
    },
    {
        .ed_type = TLSEXT_TYPE_supported_groups,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
            | FC_TLS_EXT_TLS1_2_SERVER_HELLO,
        .ed_parse_ctos = tls_parse_ctos_supported_groups,
        .ed_construct_stoc = tls_construct_stoc_supported_groups,
        .ed_construct_ctos = tls_construct_ctos_supported_groups,
    },
    {
        .ed_type = TLSEXT_TYPE_encrypt_then_mac,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_2_SERVER_HELLO
            | FC_TLS_EXT_TLS1_2_AND_BELOW_ONLY,
        .ed_init = init_etm,
        .ed_parse_ctos = tls_parse_ctos_etm,
        .ed_parse_stoc = tls_parse_stoc_etm,
        .ed_construct_stoc = tls_construct_stoc_etm,
        .ed_construct_ctos = tls_construct_ctos_etm,
    },
    {
        .ed_type = TLSEXT_TYPE_extended_master_secret,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_2_SERVER_HELLO
            | FC_TLS_EXT_TLS1_2_AND_BELOW_ONLY,
        .ed_init = init_ems,
        .ed_parse_ctos = tls_parse_ctos_ems,
        .ed_parse_stoc = tls_parse_stoc_ems,
        .ed_construct_ctos = tls_construct_ctos_ems,
        .ed_construct_stoc = tls_construct_stoc_ems,
        .ed_final = final_ems,
    },
    {
        .ed_type = TLSEXT_TYPE_signature_algorithms,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_3_SERVER_HELLO,
        .ed_init = init_sig_algs,
        .ed_parse_ctos = tls_parse_ctos_sig_algs,
        .ed_parse_stoc = tls_parse_stoc_sig_algs,
        .ed_construct_ctos = tls_construct_ctos_sig_algs,
        .ed_construct_stoc = tls_construct_stoc_sig_algs,
        .ed_final = final_sig_algs,
    },
    {
        .ed_type = TLSEXT_TYPE_supported_versions,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_3_SERVER_HELLO,
        .ed_init = NULL,
        .ed_parse_ctos = NULL,
        .ed_parse_stoc = tls_parse_stoc_supported_versions,
        .ed_construct_ctos = tls_construct_ctos_supported_versions,
        .ed_construct_stoc = tls_construct_stoc_supported_versions,
        .ed_final = NULL,
    },
    {
        .ed_type = TLSEXT_TYPE_key_share,
        .ed_context = FC_TLS_EXT_CLIENT_HELLO | FC_TLS_EXT_TLS1_3_SERVER_HELLO,
        .ed_init = NULL,
        .ed_parse_ctos = tls_parse_ctos_key_share,
        .ed_parse_stoc = tls_parse_stoc_key_share,
        .ed_construct_ctos = tls_construct_ctos_key_share,
        .ed_construct_stoc = tls_construct_stoc_key_share,
        .ed_final = final_key_share,
    },
};

#define EXTENSION_DEF_SIZE FC_ARRAY_SIZE(ext_defs)

int
tls_construct_extensions(TLS *s, WPACKET *pkt, uint32_t context,
        FC_X509 *x, size_t chainidx)
{
    const EXTENSION_DEFINITION  *thisexd = NULL;
    uint16_t                    *len = NULL;
    size_t                      written = 0;
    EXT_CONSTRUCT_F             construct = NULL;
    EXT_RETURN                  ret = 0;
    int                         i = 0;

    if (WPACKET_allocate_bytes(pkt, sizeof(*len), (unsigned char **)&len) == 0) {
        return 0;
    }

    written = pkt->wk_written;
    for (i = 0, thisexd = ext_defs; i < EXTENSION_DEF_SIZE; i++, thisexd++) {
        construct = s->tls_server ? thisexd->ed_construct_stoc
                                  : thisexd->ed_construct_ctos;
        if (construct == NULL) {
            continue;
        }
        ret = construct(s, pkt, context, x, chainidx);
        if (ret == EXT_RETURN_FAIL) {
            return 0;
        }
    }

    *len = FC_HTONS(pkt->wk_written - written);

    return 1;
}

static int
init_etm(TLS *s, unsigned int context)
{
    s->tls_ext.use_etm = 0;

    return 1;
}

static int
init_ems(TLS *s, unsigned int context)
{
    return 1;
}

static int
final_ems(TLS *s, unsigned int context, int sent)
{
    return 1;
}

static int
init_sig_algs(TLS *s, unsigned int context)
{
    return 1;
}

static int
final_sig_algs(TLS *s, unsigned int context, int sent)
{
    return 1;
}

static int
final_ec_pt_formats(TLS *s, unsigned int context, int sent)
{
    return 1;
}

static int
final_key_share(TLS *s, unsigned int context, int sent)
{
    return 1;
}

int
tls_parse_all_extensions(TLS *s, PACKET *pkt)
{
    return 1;
}

