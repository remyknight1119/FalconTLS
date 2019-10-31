
#include "tls_locl.h"
#include "tls1.h"
#include "handshake.h"

TLS_ENC_METHOD const TLSv1_3_enc_data = {
    .em_set_handshake_header = tls_set_handshake_header,
    .em_hhlen = TLS_HM_HEADER_LENGTH,
    .em_do_write = tls_handshake_write,
    .em_enc_flags = TLS_ENC_FLAG_SIGALGS,
};


