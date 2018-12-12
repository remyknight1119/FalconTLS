

#include "tls_locl.h"
#include "statem_locl.h"
#include "packet_locl.h"

int
tls_parse_stoc_etm(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

EXT_RETURN
tls_construct_ctos_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_encrypt_then_mac)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
