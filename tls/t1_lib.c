#include <arpa/inet.h>

#include <falcontls/types.h>
#include <internal/buffer.h>

#include "packet_locl.h"
#include "tls_locl.h"
#include "record_locl.h"
 
int
tls1_set_handshake_header(TLS *s, WPACKET *pkt, int mt)
{
    record_t    *r = NULL;

    r = (void *)pkt->wk_buf->bm_data;
    r->rd_version.pv_version = htons(s->tls_version);
    r->rd_type = mt;
    r->rd_len = htons(pkt->wk_written);

    s->tls_init_num = (int)pkt->wk_written + TLS_RT_HEADER_LENGTH;
    s->tls_init_off = 0;

    return 1;
}
