
#include <falcontls/types.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "cipher.h"

#define TLS_ENC_AES128_IDX      0
#define TLS_ENC_AES256_IDX      1
#define TLS_ENC_AES128GCM_IDX   2
#define TLS_ENC_AES256GCM_IDX   3
#define TLS_ENC_AES128CCM_IDX   4
#define TLS_ENC_AES256CCM_IDX   5
#define TLS_ENC_AES128CCM8_IDX  6
#define TLS_ENC_AES256CCM8_IDX  7
#define TLS_ENC_CHACHA_IDX      8
#define TLS_ENC_NUM_IDX         9

#define TLS_MD_NUM_IDX  TLS_MAX_DIGEST

typedef struct {
    uint32_t    ct_mask;
    int         ct_nid;
} tls_cipher_table;

static const FC_EVP_MD *tls_digest_methods[TLS_MD_NUM_IDX];

/* Table of NIDs for each cipher */
static const tls_cipher_table tls_cipher_table_cipher[TLS_ENC_NUM_IDX] = {
    {
        .ct_mask = TLS_AES128,
        .ct_nid = NID_aes_128_cbc,
    }, /* TLS_ENC_AES128_IDX 0 */
    {
        .ct_mask = TLS_AES256,
        .ct_nid = NID_aes_256_cbc,
    }, /* TLS_ENC_AES256_IDX 1 */
    {
        .ct_mask = TLS_AES128GCM,
        .ct_nid = NID_aes_128_gcm,
    }, /* TLS_ENC_AES128GCM_IDX 2 */
    {
        .ct_mask = TLS_AES256GCM,
        .ct_nid = NID_aes_256_gcm,
    }, /* TLS_ENC_AES256GCM_IDX 3 */
    {
        .ct_mask = TLS_AES128CCM,
        .ct_nid = NID_aes_128_ccm,
    }, /* TLS_ENC_AES128CCM_IDX 4 */
    {
        .ct_mask = TLS_AES256CCM,
        .ct_nid = NID_aes_256_ccm,
    }, /* TLS_ENC_AES256CCM_IDX 5 */
    {
        .ct_mask = TLS_AES128CCM8,
        .ct_nid = NID_aes_128_ccm,
    }, /* TLS_ENC_AES128CCM8_IDX 6 */
    {
        .ct_mask = TLS_AES256CCM8,
        .ct_nid = NID_aes_256_ccm
    }, /* TLS_ENC_AES256CCM8_IDX 7 */
    {
        .ct_mask = TLS_CHACHA20POLY1305,
        .ct_nid = NID_chacha20_poly1305,
    }, /* TLS_ENC_CHACHA_IDX 8 */
};

static int
tls_cipher_info_find(const tls_cipher_table *table,size_t table_cnt,
                        uint32_t mask)
{
    size_t  i = 0;

    for (i = 0; i < table_cnt; i++, table++) { 
        if (table->ct_mask == mask) {
            return (int)i;
        }
    }

    return -1;
}

#define tls_cipher_info_lookup(table, x) \
            tls_cipher_info_find(table, FC_ARRAY_SIZE(table), x)

const FC_EVP_MD *
tls_md(int idx)
{
    idx &= TLS_HANDSHAKE_MAC_MASK;
    if (idx < 0 || idx >= TLS_MD_NUM_IDX) {
        return NULL;
    }

    return tls_digest_methods[idx];
}

const FC_EVP_MD *
tls_handshake_md(TLS *s)
{
    return tls_md(tls_get_algorithm(s));
}

const FC_EVP_MD *
tls_prf_md(TLS *s)
{
    return tls_md(tls_get_algorithm(s) >> TLS1_PRF_DGST_SHIFT);
}

const TLS_CIPHER *
tls_search_cipher_byid(const TLS_CIPHER *ciphers, size_t num, uint32_t id)
{
    const TLS_CIPHER    *cipher = NULL;
    int                 i = 0;

    for (i = 0; i < num; i++) {
        cipher = &ciphers[i];
        if (cipher->cp_id == id) {
            return cipher;
        }
    }

    FC_LOG("find cipher failed\n");
    return NULL;
}

int 
tls_put_cipher_by_char(const TLS_CIPHER *c, WPACKET *pkt, size_t *len)
{
    if (!WPACKET_put_bytes_u16(pkt, c->cp_id & 0xffff)) {
        return 0;
    }

    *len = sizeof(uint16_t);
    return 1;
}

int
tls_cipher_get_evp(const TLS_SESSION *s, const FC_EVP_CIPHER **enc,
        const FC_EVP_MD **md, int *mac_pkey_type,
        size_t *mac_secret_size, int use_etm)
{
    const TLS_CIPHER    *c = NULL;
    int                 i = 0;

    c = s->se_cipher;
    if (c == NULL) {
        FC_LOG("No cipher\n");
        return 0;
    }

    if ((enc == NULL) || (md == NULL)) {
        return 0;
    }

    i = tls_cipher_info_lookup(tls_cipher_table_cipher, c->cp_algorithm_enc);
    if (i == -1) {
        *enc = NULL;
        return 0;
    }

    i = tls_cipher_info_lookup(tls_cipher_table_mac, c->cp_algorithm_mac);
    if (i == -1) {
        return 0;
    }
}

