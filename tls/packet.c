#include <assert.h>

#include <falcontls/types.h>

#include "packet_locl.h"
#include "record_locl.h"

int
WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf, size_t hlen)
{
    pkt->wk_buf = buf;
    pkt->wk_curr = hlen;

    assert(buf->bm_max > pkt->wk_curr);
    pkt->wk_maxsize = buf->bm_max - pkt->wk_curr;

    return 1;
}
