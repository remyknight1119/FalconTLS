#include <falcontls/tls.h>
#include <falcontls/tls1_2.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_lib.h>
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

static TLS_CIPHER tls1_2_ciphers[] = {
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
#if 0
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
#endif
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

int
tls1_2_num_ciphers(void)
{
    return TLS1_2_NUM_CIPHERS;
}

const TLS_CIPHER *
tls1_2_get_cipher(uint32_t u)
{
    if (u >= TLS1_2_NUM_CIPHERS) {
        return NULL;
    }

    return (&(tls1_2_ciphers[TLS1_2_NUM_CIPHERS - 1 - u]));
}

static const TLS_CIPHER *
tls1_2_search_cipher_byid(uint32_t id)
{
    const TLS_CIPHER    *cipher = NULL;
    int                 i = 0;

    for (i = 0; i < TLS1_2_NUM_CIPHERS; i++) {
        cipher = &tls1_2_ciphers[i];
        if (cipher->cp_id == id) {
            return cipher;
        }
    }

    FC_LOG("find cipher failed\n");
    return NULL;
}

const TLS_CIPHER *
tls1_2_get_cipher_by_char(const uint8_t *p)
{
    uint32_t    id = 0;

    id = 0x03000000 | FC_NTOHS(*((uint16_t *)p));
    return tls1_2_search_cipher_byid(id);
}

int 
tls1_2_put_cipher_by_char(const TLS_CIPHER *c, uint8_t *p)
{
    uint32_t    l = 0;

    if (p != NULL) {
        l = c->cp_id;
        if ((l & 0xFF000000) != 0x03000000) {
            return (0);
        }
        *((uint16_t *)p) = FC_HTONS(l & 0xFFFF);
    }

    return (sizeof(uint16_t));
}


