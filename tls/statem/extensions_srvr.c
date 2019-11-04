

#include "tls_locl.h"
#include "statem_locl.h"
#include "packet_locl.h"

int
tls_parse_ctos_etm(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_ctos_ems(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_ctos_sig_algs(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_ctos_ec_pt_formats(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_ctos_supported_groups(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return 1;
}

int
tls_parse_ctos_key_share(TLS *s, PACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return 1;
}


EXT_RETURN
tls_construct_stoc_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_stoc_ems(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_stoc_sig_algs(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_stoc_ec_pt_formats(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_stoc_supported_groups(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_stoc_supported_versions(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_stoc_key_share(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    return EXT_RETURN_SENT;
}



