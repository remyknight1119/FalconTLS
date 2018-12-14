#include <assert.h>
#include <string.h>

#include <falcontls/types.h>

#include "packet_locl.h"
#include "record_locl.h"

#define GETBUF(p)       (unsigned char *)(p)->wk_buf->bm_data

unsigned char *
WPACKET_get_curr(WPACKET *pkt)
{
    return GETBUF(pkt) + pkt->wk_curr;
}

int
WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (allocbytes != NULL) {
        *allocbytes = WPACKET_get_curr(pkt);
    }

    return 1;
}

int
WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (!WPACKET_reserve_bytes(pkt, len, allocbytes)) {
        return 0;
    }

    pkt->wk_written += len;
    pkt->wk_curr += len;
    return 1;
}


int
WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf, size_t hlen)
{
    pkt->wk_buf = buf;
    pkt->wk_curr = hlen;

    assert(buf->bm_max > pkt->wk_curr);
    pkt->wk_maxsize = buf->bm_max - pkt->wk_curr;

    return 1;
}

/* Store the |value| of length |len| at location |data| */
static int
put_value(unsigned char *data, size_t value, size_t len)
{
    for (data += len - 1; len > 0; len--) {
        *data = (unsigned char)(value & 0xff);
        data--;
        value >>= 8;
    }

    /* Check whether we could fit the value in the assigned number of bytes */
    if (value > 0) {
        return 0;
    }

    return 1;
}

int
WPACKET_put_bytes(WPACKET *pkt, unsigned int val, size_t size)
{
    unsigned char   *data = NULL;

    /* Internal API, so should not fail */
    assert(size <= sizeof(unsigned int));
    if (!WPACKET_allocate_bytes(pkt, size, &data)
            || !put_value(data, val, size)) {
        return 0;
    }

    return 1;
}

int
WPACKET_memset(WPACKET *pkt, int ch, size_t len)
{
    unsigned char   *dest = NULL;

    if (len == 0)
        return 1;

    if (!WPACKET_allocate_bytes(pkt, len, &dest)) {
        return 0;
    }

    memset(dest, ch, len);

    return 1;
}

int
WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
    unsigned char   *dest = NULL;

    if (len == 0) {
        return 1;
    }

    if (!WPACKET_allocate_bytes(pkt, len, &dest)) {
        return 0;
    }

    memcpy(dest, src, len);

    return 1;
}


