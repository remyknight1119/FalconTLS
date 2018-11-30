#ifndef __PACKET_LOCL_H__
#define __PACKET_LOCL_H__

#include <falcontls/types.h>
#include <internal/buffer.h>

typedef struct {
    /* Pointer to where we are currently reading from */
    const uint8_t   *pk_curr;
    /* Number of bytes remaining */
    size_t          pk_remaining;
} PACKET;

/* Internal unchecked shorthand; don't use outside this file. */
static inline void packet_forward(PACKET *pkt, size_t len)
{
    pkt->pk_curr += len;
    pkt->pk_remaining -= len;
}


typedef struct wpacket_t {
    /* The buffer where we store the output data */
    FC_BUF_MEM      *wk_buf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t          wk_curr;

    /* Number of bytes written so far */
    size_t          wk_written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t          wk_maxsize;
} WPACKET;

int WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf, size_t hlen);

#endif
