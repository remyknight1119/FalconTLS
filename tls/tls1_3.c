
#include "tls_locl.h"
#include "tls1.h"
#include "tls1_3.h"
#include "handshake.h"
#include "cipher.h"

TLS_ENC_METHOD const TLSv1_3_enc_data = {
    .em_set_handshake_header = tls_set_handshake_header,
    .em_setup_key_block = tls13_setup_key_block,
    .em_change_cipher_state = tls13_change_cipher_state,
    .em_hhlen = TLS_HM_HEADER_LENGTH,
    .em_do_write = tls_handshake_write,
    .em_enc_flags = TLS_ENC_FLAG_SIGALGS,
};

static TLS_CIPHER tls1_3_ciphers[] = {
    {
        .cp_name = TLS1_3_RFC_AES_128_GCM_SHA256,
        .cp_id = TLS1_3_CK_AES_128_GCM_SHA256,
        .cp_algorithm_mkey = TLS_kANY,
        .cp_algorithm_auth = TLS_aANY,
        .cp_algorithm_enc = TLS_AES128GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_min_tls = FC_TLS1_3_VERSION,
        .cp_max_tls = FC_TLS1_3_VERSION,
        .cp_algorithm = TLS_HANDSHAKE_MAC_SHA256, 
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_3_RFC_AES_256_GCM_SHA384,
        .cp_id = TLS1_3_CK_AES_256_GCM_SHA384,
        .cp_algorithm_mkey = TLS_kANY,
        .cp_algorithm_auth = TLS_aANY,
        .cp_algorithm_enc = TLS_AES256GCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_min_tls = FC_TLS1_3_VERSION,
        .cp_max_tls = FC_TLS1_3_VERSION,
        .cp_algorithm = TLS_HANDSHAKE_MAC_SHA384, 
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        .cp_id = TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        .cp_algorithm_mkey = TLS_kANY,
        .cp_algorithm_auth = TLS_aANY,
        .cp_algorithm_enc = TLS_CHACHA20POLY1305,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_min_tls = FC_TLS1_3_VERSION,
        .cp_max_tls = FC_TLS1_3_VERSION,
        .cp_algorithm = TLS_HANDSHAKE_MAC_SHA256, 
        .cp_alg_bits = 256,
        .cp_strength_bits = 256,
    },
    {
        .cp_name = TLS1_3_RFC_AES_128_CCM_SHA256,
        .cp_id = TLS1_3_CK_AES_128_CCM_SHA256,
        .cp_algorithm_mkey = TLS_kANY,
        .cp_algorithm_auth = TLS_aANY,
        .cp_algorithm_enc = TLS_AES128CCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_min_tls = FC_TLS1_3_VERSION,
        .cp_max_tls = FC_TLS1_3_VERSION,
        .cp_algorithm = TLS_HANDSHAKE_MAC_SHA256, 
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
        .cp_name = TLS1_3_RFC_AES_128_CCM_8_SHA256,
        .cp_id = TLS1_3_CK_AES_128_CCM_8_SHA256,
        .cp_algorithm_mkey = TLS_kANY,
        .cp_algorithm_auth = TLS_aANY,
        .cp_algorithm_enc = TLS_AES128CCM8,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_min_tls = FC_TLS1_3_VERSION,
        .cp_max_tls = FC_TLS1_3_VERSION,
        .cp_algorithm = TLS_HANDSHAKE_MAC_SHA256, 
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
};

#define TLS1_3_NUM_CIPHERS  FC_ARRAY_SIZE(tls1_3_ciphers)
 
int
tls1_3_num_ciphers(void)
{
    return TLS1_3_NUM_CIPHERS;
}

const TLS_CIPHER *
tls1_3_get_cipher(uint32_t u)
{
    if (u >= TLS1_3_NUM_CIPHERS) {
        return NULL;
    }

    return (&(tls1_3_ciphers[TLS1_3_NUM_CIPHERS - 1 - u]));
}

static const TLS_CIPHER *
tls1_3_search_cipher_byid(uint32_t id)
{
    return tls_search_cipher_byid(tls1_3_ciphers, TLS1_3_NUM_CIPHERS, id);
}

const TLS_CIPHER *
tls1_3_get_cipher_by_char(const uint8_t *p)
{
    uint32_t    id = 0;

    id = 0x03000000 | FC_NTOHS(*((uint16_t *)p));
    return tls1_3_search_cipher_byid(id);
}


