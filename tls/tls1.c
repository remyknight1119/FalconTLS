
#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls1.h"
#include "tls_locl.h"

int
tls_handshake_write(TLS *s)
{
    return tls_do_write(s, TLS_RT_HANDSHAKE);
}

int
tls_set_handshake_header(TLS *s, WPACKET *pkt, int htype)
{
    if (htype == TLS_MT_CHANGE_CIPHER_SPEC) {
        return 1;
    }

    if (WPACKET_put_bytes_u8(pkt, htype)  == 0 ||
            WPACKET_start_sub_packet_u24(pkt) == 0) {
        FC_LOG("WPACKET error!\n");
        return 0;
    }

    return 1;
}


