#include <assert.h>
#include <string.h>

#include <falcontls/types.h>
#include <fc_log.h>

#include "packet_locl.h"
#include "record_locl.h"

unsigned char *
WPACKET_get_curr(WPACKET *pkt)
{
    return WPKT_GETBUF(pkt) + pkt->wk_curr;
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

static int
wpacket_intern_init_len(WPACKET *pkt, size_t lenbytes)
{
    unsigned char   *lenchars = NULL;

    pkt->wk_curr = 0;
    pkt->wk_written = 0;

    if ((pkt->wk_subs = FALCONTLS_calloc(sizeof(*pkt->wk_subs))) == NULL) {
        return 0;
    }

    if (lenbytes == 0) {
        return 1;
    }

    pkt->wk_subs->ws_pwritten = lenbytes;
    pkt->wk_subs->ws_lenbytes = lenbytes;

    if (!WPACKET_allocate_bytes(pkt, lenbytes, &lenchars)) {
        FALCONTLS_free(pkt->wk_subs);
        pkt->wk_subs = NULL;
        FC_LOG("WPACKET allocate error!\n");
        return 0;
    }
    pkt->wk_subs->ws_packet_len = lenchars - WPKT_GETBUF(pkt);

    return 1;
}


int
WPACKET_init_len(WPACKET *pkt, FC_BUF_MEM *buf, size_t lenbytes)
{
    assert(buf != NULL);

   // pkt->staticbuf = NULL;
    pkt->wk_buf = buf;
    pkt->wk_maxsize = lenbytes;

    return wpacket_intern_init_len(pkt, lenbytes);
}

int
WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf)
{
    return WPACKET_init_len(pkt, buf, 0);
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
WPACKET_set_max_size(WPACKET *pkt, size_t maxsize)
{
    pkt->wk_maxsize = maxsize;

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
        FC_LOG("fail\n");
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

int
WPACKET_start_sub_packet_len(WPACKET *pkt, size_t lenbytes)
{
    WPACKET_SUB     *sub = NULL;
    unsigned char   *lenchars = NULL;

    /* Internal API, so should not fail */
    assert(pkt->wk_subs != NULL);

    if ((sub = FALCONTLS_calloc(sizeof(*sub))) == NULL) {
        return 0;
    }

    sub->ws_parent = pkt->wk_subs;
    pkt->wk_subs = sub;
    sub->ws_pwritten = pkt->wk_written + lenbytes;
    sub->ws_lenbytes = lenbytes;

    if (lenbytes == 0) {
        sub->ws_packet_len = 0;
        return 1;
    }

    if (!WPACKET_allocate_bytes(pkt, lenbytes, &lenchars)) {
        FC_LOG("fail\n");
        return 0;
    }
    /* Convert to an offset in case the underlying BUF_MEM gets realloc'd */
    sub->ws_packet_len = lenchars - WPKT_GETBUF(pkt);

    return 1;
}

int WPACKET_start_sub_packet(WPACKET *pkt)
{
    return WPACKET_start_sub_packet_len(pkt, 0);
}


static int
wpacket_intern_close(WPACKET *pkt, WPACKET_SUB *sub, int doclose)
{
    unsigned char   *buf = NULL;
    size_t          packlen = pkt->wk_written - sub->ws_pwritten;

    buf = WPKT_GETBUF(pkt);
    /* Write out the WPACKET length if needed */
    if (sub->ws_lenbytes > 0
            && !put_value(&buf[sub->ws_packet_len], packlen,
                sub->ws_lenbytes)) {
        return 0;
    }

    if (doclose) {
        pkt->wk_subs = sub->ws_parent;
        FALCONTLS_free(sub);
    }

    return 1;
}

int
WPACKET_close(WPACKET *pkt)
{
    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->wk_subs == NULL || pkt->wk_subs->ws_parent == NULL) {
        return 0;
    }

    return wpacket_intern_close(pkt, pkt->wk_subs, 1);
}

int
WPACKET_get_length(WPACKET *pkt, size_t *len)
{
    /* Internal API, so should not fail */
    assert(pkt->wk_subs != NULL && len != NULL);

    *len = pkt->wk_written - pkt->wk_subs->ws_pwritten;

    return 1;
}

int
WPACKET_finish(WPACKET *pkt)
{
    int         ret = 0;

    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->wk_subs == NULL || pkt->wk_subs->ws_parent != NULL) {
        return 0;
    }

    ret = wpacket_intern_close(pkt, pkt->wk_subs, 1);
    if (ret) {
        FALCONTLS_free(pkt->wk_subs);
        pkt->wk_subs = NULL;
    }

    return ret;
}

void
WPACKET_cleanup(WPACKET *pkt)
{
    WPACKET_SUB     *sub = NULL;
    WPACKET_SUB     *parent = NULL;

    for (sub = pkt->wk_subs; sub != NULL; sub = parent) {
        parent = sub->ws_parent;
        FALCONTLS_free(sub);
    }
    pkt->wk_subs = NULL;
}

