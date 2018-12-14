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

int WPACKET_put_bytes(WPACKET *pkt, unsigned int val, size_t bytes);

/*
 * Convenience macros for calling WPACKET_put_bytes with different
 * lengths
 */
#define WPACKET_put_bytes_u8(pkt, val) \
    WPACKET_put_bytes((pkt), (val), 1)
#define WPACKET_put_bytes_u16(pkt, val) \
    WPACKET_put_bytes((pkt), (val), 2)
#define WPACKET_put_bytes_u24(pkt, val) \
    WPACKET_put_bytes((pkt), (val), 3)
#define WPACKET_put_bytes_u32(pkt, val) \
    WPACKET_put_bytes((pkt), (val), 4)


int WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf, size_t hlen);

/*
 * Write the value stored in |val| into the WPACKET. The value will consume
 * |bytes| amount of storage. An error will occur if |val| cannot be
 * accommodated in |bytes| storage, e.g. attempting to write the value 256 into
 * 1 byte will fail. Don't call this directly. Use the convenience macros below
 * instead.
 */
int WPACKET_put_bytes(WPACKET *pkt, unsigned int val, size_t size);
int WPACKET_memset(WPACKET *pkt, int ch, size_t len);
int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len);
int WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes);

#endif
