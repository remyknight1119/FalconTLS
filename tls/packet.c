#include <assert.h>

#include <falcontls/types.h>
#include <internal/buffer.h>

#include "packet_locl.h"
#include "record_locl.h"

int
WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf)
{
    pkt->wk_buf = buf;
    pkt->wk_curr = TLS_RT_HEADER_LENGTH;

    assert(buf->bm_max > pkt->wk_curr);
    pkt->wk_maxsize = buf->bm_max - pkt->wk_curr;

    return 1;
}
