#ifndef __STATME_LOCL_H__
#define __STATME_LOCL_H__

#include <falcontls/types.h>
#include <falcontls/tls.h>

#include "packet_locl.h"
#include "tls_locl.h"

/* Extension processing */

typedef enum ext_return_en {
    EXT_RETURN_FAIL,
    EXT_RETURN_SENT,
    EXT_RETURN_NOT_SENT
} EXT_RETURN;

int tls_parse_ctos_etm(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx);
int tls_parse_stoc_etm(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx);
int tls_parse_ctos_ems(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx);
int tls_parse_stoc_ems(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx);
int tls_parse_ctos_sig_algs(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx);
int tls_parse_stoc_sig_algs(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx);
int tls_parse_ctos_ec_pt_formats(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
int tls_parse_stoc_ec_pt_formats(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
int tls_parse_ctos_supported_groups(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
int tls_parse_stoc_supported_versions(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
int tls_parse_ctos_key_share(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
int tls_parse_stoc_key_share(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
int tls_construct_extensions(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_ems(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_ems(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_sig_algs(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_sig_algs(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_ec_pt_formats(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_ec_pt_formats(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_supported_groups(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_supported_groups(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_supported_versions(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_supported_versions(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_key_share(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_key_share(TLS *s, WPACKET *pkt,
                    uint32_t context, FC_X509 *x, size_t chainidx);

int tls_parse_all_extensions(TLS *s, PACKET *pkt);
int tls_collect_extensions(TLS *s, PACKET *packet, unsigned int context,
                        RAW_EXTENSION **res, size_t *len, int init);

int parse_ca_names(TLS *s, PACKET *pkt);
int tls_output_cert_chain(TLS *s, WPACKET *pkt, CERT_PKEY *cpk);
int tls_close_construct_packet(TLS *s, WPACKET *pkt, int htype);
int tls_get_min_max_version(const TLS *s, int *min_version, int *max_version);
int tls_choose_client_version(TLS *s, int version, RAW_EXTENSION *extensions);

#endif
