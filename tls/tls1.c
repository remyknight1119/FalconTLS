
#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls1.h"
#include "tls_locl.h"
#include "record.h"
#include "handshake.h"

static int tls_enc(TLS *s, TLS_RECORD *recs, size_t n_recs, int sending);

TLS_ENC_METHOD const TLS_enc_data = {
    .em_enc = tls_enc,
    .em_set_handshake_header = tls_set_handshake_header,
    .em_hhlen = TLS_HM_HEADER_LENGTH,
    .em_do_write = tls_handshake_write,
    .em_enc_flags = TLS_ENC_FLAG_SIGALGS,
};

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

static int
tls_enc(TLS *s, TLS_RECORD *recs, size_t n_recs, int sending)
{
    FC_EVP_CIPHER_CTX   *ds = NULL;
    const FC_EVP_CIPHER *enc = NULL;
    size_t              ctr = 0;
    int                 ret = -1;

    if ((s->tls_session == NULL) || (ds == NULL) || (enc == NULL)) {
        for (ctr = 0; ctr < n_recs; ctr++) {
            memmove(recs[ctr].rd_data, recs[ctr].rd_input, recs[ctr].rd_length);
            recs[ctr].rd_input = recs[ctr].rd_data;
        }
        ret = 1;
    } else {
    }

    return ret;
}
