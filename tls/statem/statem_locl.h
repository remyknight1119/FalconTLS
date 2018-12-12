#ifndef __STATME_LOCL_H__
#define __STATME_LOCL_H__

#include <falcontls/types.h>
#include <falcontls/tls.h>

#include "packet_locl.h"

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
int tls_construct_extensions(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_ctos_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);
EXT_RETURN tls_construct_stoc_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx);

#endif
