#ifndef __PACKET_LOCL_H__
#define __PACKET_LOCL_H__

#include <falcontls/types.h>
#include <internal/buffer.h>
#include <fc_lib.h>

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

/*
 * Returns the number of bytes remaining to be read in the PACKET
 */
static inline size_t PACKET_remaining(const PACKET *pkt)
{
    return pkt->pk_remaining;
}

/*
 * Returns a pointer to the PACKET's current position.
 * For use in non-PACKETized APIs.
 */
static inline const unsigned char *PACKET_data(const PACKET *pkt)
{
    return pkt->pk_curr;
}

/*
 * Initialise a PACKET with |len| bytes held in |buf|. This does not make a
 * copy of the data so |buf| must be present for the whole time that the PACKET
 * is being used.
 */
static inline int PACKET_buf_init(PACKET *pkt, const unsigned char *buf,
                                    size_t len)
{
    pkt->pk_curr = buf;
    pkt->pk_remaining = len;

    return 1;
}

#define DEFINE_PACKET_GET(name, num, type) \
    static inline int PACKET_peek##name##num(const PACKET *pkt, \
                                    type *data) \
    { \
        if (PACKET_remaining(pkt) < num) { \
            return 0; \
        } \
    \
        set_h##num(data, pkt->pk_curr, type); \
    \
        return 1; \
    } \
    \
    static inline int PACKET_get##name##num(PACKET *pkt, type *data) \
    { \
        if (!PACKET_peek##name##num(pkt, data)) { \
            return 0; \
        } \
    \
        packet_forward(pkt, num); \
    \
        return 1; \
    } \
    \
    static inline int PACKET_get##name##num##_len(PACKET *pkt, size_t *data) \
    { \
        type            i = 0; \
        int             ret = PACKET_get##name##num(pkt, &i); \
    \
        if (ret) { \
            *data = (size_t)i; \
        } \
    \
        return ret;\
    }

#define DEFINE_PACKET_GET_NET(num, type) DEFINE_PACKET_GET(_net_, num, type)

DEFINE_PACKET_GET(_, 1, unsigned int)

DEFINE_PACKET_GET_NET(2, unsigned int)

DEFINE_PACKET_GET_NET(3, unsigned long)

DEFINE_PACKET_GET_NET(4, unsigned long)

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

#define WPKT_GETBUF(p)      (unsigned char *)GET_BUF_DATA((p)->wk_buf)

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
