#include <falcontls/tls.h>
#include <falcontls/tls1_2.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "record.h"
#include "handshake.h"
#include "cipher.h"

static int tls1_2_set_handshake_header(TLS *s, WPACKET *pkt, int mt);

TLS_ENC_METHOD const TLSv1_2_enc_data = {
    .em_set_handshake_header = tls1_2_set_handshake_header,
    .em_hhlen = TLS_HM_HEADER_LENGTH,
    .em_do_write = tls1_2_handshake_write,
};

 TLS_CIPHER tls1_2_ciphers[] = {
    {
        .cp_name = TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
        .cp_id = TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
        .cp_algorithm_mkey = TLS_kDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_AES128GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
        .cp_id = TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
        .cp_algorithm_mkey = TLS_kDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_AES256GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_DHE_RSA_WITH_AES_128_CCM,
        .cp_id = TLS1_CK_DHE_RSA_WITH_AES_128_CCM,
        .cp_algorithm_mkey = TLS_kDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_AES128CCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_TXT_DHE_RSA_WITH_AES_256_CCM,
        .cp_id = TLS1_CK_DHE_RSA_WITH_AES_256_CCM,
        .cp_algorithm_mkey = TLS_kDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_AES256CCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM,
        .cp_id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aECDSA,
        .cp_algorithm_enc = TLS_AES128CCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM,
        .cp_id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aECDSA,
        .cp_algorithm_enc = TLS_AES256CCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .cp_id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aECDSA,
        .cp_algorithm_enc = TLS_AES128GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .cp_id = TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aECDSA,
        .cp_algorithm_enc = TLS_AES256GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .cp_id = TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_AES128GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .cp_id = TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_AES256GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
        .cp_id = TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305,
        .cp_algorithm_mkey = TLS_kDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_CHACHA20POLY1305,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        .cp_id = TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aRSA,
        .cp_algorithm_enc = TLS_CHACHA20POLY1305,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        .cp_id = TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_algorithm_auth = TLS_aECDSA,
        .cp_algorithm_enc = TLS_CHACHA20POLY1305,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
};
 
#define TLS1_2_NUM_CIPHERS  FC_ARRAY_SIZE(tls1_2_ciphers)

int 
tls1_2_new(TLS *s)
{
    return 1;
}

void
tls1_2_clear(TLS *s)
{
}

void
tls1_2_free(TLS *s)
{
}

int
tls1_2_accept(TLS *s)
{
    return 1;
}

int
tls1_2_connect(TLS *s)
{
    return 1;
}

int
tls1_2_read(TLS *s, void *buf, int len)
{
    return 1;
}

int
tls1_2_peek(TLS *s, void *buf, int len)
{
    return 1;
}

int
tls1_2_handshake_write(TLS *s)
{
    return tls_do_write(s, TLS1_2_RT_HANDSHAKE);
}

int
tls1_2_set_handshake_header(TLS *s, WPACKET *pkt, int mt)
{
    handshake_t     *h = NULL;
    uint8_t         *len = NULL;

    h = (void *)pkt->wk_buf->bm_data;
    h->hk_type  = mt;
    len = &h->hk_len[0];
    l2n3(pkt->wk_written, len);

    s->tls_init_num = (int)pkt->wk_written + TLS_HM_HEADER_LENGTH;
    s->tls_init_off = 0;

    return 1;
}


