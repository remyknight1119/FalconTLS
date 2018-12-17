#include <string.h>
#include <falcontls/tls.h>
#include <falcontls/bio.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"

static int
tls_write_pending(TLS *s)
{
    TLS_BUFFER  *wb = s->tls_rlayer.rl_wbuf; 
    int          wlen = 0;

    if (s->tls_wbio == NULL) {
        return -1;
    }
    
    wlen = FC_BIO_write(s->tls_wbio, TLS_BUFFER_get_buf(wb),
            TLS_BUFFER_get_offset(wb));
    if (wlen < 0) {
        return -1;
    }

    FC_LOG("wlen = %d\n", wlen);
    return 0;
}

int
tls_write_bytes(TLS *s, int type, const void *buf, size_t len,
        size_t *written)
{
    TLS_BUFFER  *wb = s->tls_rlayer.rl_wbuf; 
    char        *b = NULL;
    int         tot_len = 0;
    int         offset = 0;
    int         wlen = 0;

    b = (void *)TLS_BUFFER_get_buf(wb);
    offset = TLS_RT_HEADER_LENGTH;
    memcpy(b + offset, buf, len);
    tls_set_record_header(s, b, len, type);
    tot_len = len + offset;
    TLS_BUFFER_add_offset(wb, tot_len);
    wlen = tls_write_pending(s);
    if (wlen < 0) {
        return -1;
    }

    *written = (size_t)len;
    FC_LOG("wlen = %d\n", wlen);
    return 0;
}

int
tls_read_n(TLS *s, size_t n, size_t max, int extend, int clearold,
        size_t *readbytes)
{
    TLS_BUFFER      *rb = NULL;
    uint8_t         *pkt = NULL;
    size_t          len = 0;
    size_t          bioread = 0;
    int             left = 0;
    int             ret = 0;

    if (n == 0) {
        return 0;
    }

    rb = RECORD_LAYER_get_rbuf(&s->tls_rlayer);
    left = rb->bf_left;
    if (left >= n) {
        goto out;
    }

    if (max < n) {
        max = n;
    }

    if (max > rb->bf_len - rb->bf_offset) {
        max = rb->bf_len - rb->bf_offset;
    }

    len = RECORD_LAYER_get_packet_length(&s->tls_rlayer);
    pkt = rb->bf_buf + rb->bf_offset;
    while (left < n) {
        ret = FC_BIO_read(s->tls_rbio, pkt + len + left, max - left);
        if (ret >= 0) {
            bioread = ret;
        }

        if (ret <= 0) {
            TLS_BUFFER_set_left(rb, left);
            return ret;
        }
        left += bioread;
    }

out:
    TLS_BUFFER_set_left(rb, left -n);
    TLS_BUFFER_add_offset(rb, n);
    RECORD_LAYER_add_packet_length(&s->tls_rlayer, n);
    *readbytes = n;
    return 1;
}

int
tls_get_record(TLS *s)
{
    TLS_RECORD      *rr = NULL;
    TLS_RECORD      *thisrr = NULL;
    TLS_BUFFER      *rbuf = NULL;
    RECORD_LAYER    *rlayer = NULL;
    size_t          num_recs = 0;
    size_t          max_recs = 0;
    size_t          more = 0;
    size_t          n = 0;
    unsigned int    type = 0;
    PACKET          pkt = {};
    int             rret = 0;

    rlayer = &s->tls_rlayer;
    rr = RECORD_LAYER_get_rrec(rlayer);
    rbuf = RECORD_LAYER_get_rbuf(rlayer);
 
    max_recs = s->tls_max_pipelines;
    if (max_recs == 0) {
        max_recs = 1;
    }

    do {
        thisrr = &rr[num_recs];
 
        if ((RECORD_LAYER_get_rstate(rlayer) != TLS_ST_READ_BODY) ||
                (RECORD_LAYER_get_packet_length(rlayer)
             < TLS_RT_HEADER_LENGTH)) {
            rret = tls_read_n(s, TLS_RT_HEADER_LENGTH,
                               TLS_BUFFER_get_len(rbuf), 0,
                               num_recs == 0 ? 1 : 0, &n);
            if (rret <= 0) {
                return rret;     /* error or non-blocking */
            }
        
            RECORD_LAYER_set_rstate(rlayer, TLS_ST_READ_BODY);
            if (!PACKET_buf_init(&pkt, RECORD_LAYER_get_packet(rlayer),
                    RECORD_LAYER_get_packet_length(rlayer))) {
                return -1;
            }

            if (!PACKET_get_1(&pkt, &type)
                    || !PACKET_get_net_2(&pkt, &thisrr->rd_rec_version)
                    || !PACKET_get_net_2_len(&pkt, &thisrr->rd_length)) {
                return -1;
            }

            thisrr->rd_type = type;
        }

        more = thisrr->rd_length;
        if (more > 0) {
            /* now s->packet_length == SSL3_RT_HEADER_LENGTH */

            rret = tls_read_n(s, more, more, 1, 0, &n);
            if (rret <= 0) {
                return rret;     /* error or non-blocking io */
            }
        }

        thisrr->rd_input = &(RECORD_LAYER_get_packet(rlayer)[TLS_RT_HEADER_LENGTH]);
        thisrr->rd_data = thisrr->rd_input;
        /* set state for later operations */
        RECORD_LAYER_set_rstate(&s->tls_rlayer, TLS_ST_READ_HEADER);

        num_recs++;

        RECORD_LAYER_reset_packet_length(rlayer);
        RECORD_LAYER_clear_first_record(rlayer);
    } while (num_recs < max_recs && thisrr->rd_type == TLS_RT_APPLICATION_DATA);

    return 1;
}

int
tls1_2_read_bytes(TLS *s, int type, int *recvd_type, void *buf, size_t len,
        size_t *read_bytes)
{
    TLS_RECORD     *rr = NULL;
    size_t          n = 0;
    size_t          totalbytes = 0;
    int             ret = 0;

    rr = RECORD_LAYER_get_rrec(&s->tls_rlayer);

start:
    FC_LOG("in\n");
    ret = tls_get_record(s);
    if (ret <= 0) {
        return ret;
    }

    if (type == TLS_RECORD_get_type(rr)) {
        if (recvd_type != NULL) {
            *recvd_type = TLS_RECORD_get_type(rr);
        }

        totalbytes = 0;
        do {
            if (len - totalbytes > TLS_RECORD_get_length(rr)) {
                n = TLS_RECORD_get_length(rr);
            } else {
                n = len - totalbytes;
            }

            memcpy(buf, &(rr->rd_data[rr->rd_off]), n);
            buf += n;
            TLS_RECORD_sub_length(rr, n);
            TLS_RECORD_add_off(rr, n);
            totalbytes += n;
        } while (type == TLS_RT_APPLICATION_DATA && totalbytes < len);

        if (totalbytes == 0) {
            /* We must have read empty records. Get more data */
            goto start;
        }

        *read_bytes = totalbytes;
        FC_LOG("out\n");
        return 1;
    }

    return 1;
}

