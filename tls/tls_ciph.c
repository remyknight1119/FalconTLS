
#include <falcontls/types.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "cipher.h"

typedef struct {
    const uint32_t              ct_mask;
    const int                   ct_nid;
    union {
        const FC_EVP_CIPHER     *ct_cipher;
        struct {
            const FC_EVP_MD     *ct_md;
            int                 ct_pkey_type;
            int                 ct_secret_size;
        };
    };
} tls_cipher_table;

typedef struct {
    char        *cem_cipher_name;
    uint64_t    cem_algorithm_enc;
    uint64_t    cem_algorithm_mac;
} tls_cipher_enc_md;

static tls_cipher_table tls_cipher_table_cipher[] = {
    {
        .ct_mask = TLS_AES128,
        .ct_nid = NID_aes_128_cbc,
    },
    {
        .ct_mask = TLS_AES256,
        .ct_nid = NID_aes_256_cbc,
    },
    {
        .ct_mask = TLS_AES128GCM,
        .ct_nid = NID_aes_128_gcm,
    },
    {
        .ct_mask = TLS_AES256GCM,
        .ct_nid = NID_aes_256_gcm,
    },
    {
        .ct_mask = TLS_AES128CCM,
        .ct_nid = NID_aes_128_ccm,
    },
    {
        .ct_mask = TLS_AES256CCM,
        .ct_nid = NID_aes_256_ccm,
    },
    {
        .ct_mask = TLS_AES128CCM8,
        .ct_nid = NID_aes_128_ccm,
    },
    {
        .ct_mask = TLS_AES256CCM8,
        .ct_nid = NID_aes_256_ccm
    },
    {
        .ct_mask = TLS_CHACHA20POLY1305,
        .ct_nid = NID_chacha20_poly1305,
    },
};

#define TLS_ENC_NUM_IDX     FC_ARRAY_SIZE(tls_cipher_table_cipher)

static tls_cipher_table tls_cipher_table_mac[] = {
    {
        .ct_mask = TLS_MD5,
        .ct_nid = NID_md5,
        .ct_pkey_type = FC_EVP_PKEY_HMAC,
    },
    {
        .ct_mask = TLS_SHA1,
        .ct_nid = NID_sha1,
        .ct_pkey_type = FC_EVP_PKEY_HMAC,
    },
    {
        .ct_mask = TLS_SHA256,
        .ct_nid = NID_sha256,
        .ct_pkey_type = FC_EVP_PKEY_HMAC,
    },
    {
        .ct_mask = TLS_SHA384,
        .ct_nid = NID_sha384,
        .ct_pkey_type = FC_EVP_PKEY_HMAC,
    },
    {
        .ct_mask = 0,
        .ct_nid = NID_md5_sha1,
        .ct_pkey_type = EVP_PKEY_NONE,
    },
    {
        .ct_mask = 0,
        .ct_nid = NID_sha224,
        .ct_pkey_type = EVP_PKEY_NONE,
    },
    {
        .ct_mask = 0,
        .ct_nid = NID_sha512,
        .ct_pkey_type = EVP_PKEY_NONE,
    },
};

#define TLS_MD_NUM_IDX     FC_ARRAY_SIZE(tls_cipher_table_mac)


static tls_cipher_enc_md cipher_enc_md[] = {
    {
        .cem_cipher_name = "AES-128-CBC-HMAC-SHA1",
        .cem_algorithm_enc = TLS_AES128,
        .cem_algorithm_mac = TLS_SHA1,
    },
    {
        .cem_cipher_name = "AES-256-CBC-HMAC-SHA1",
        .cem_algorithm_enc = TLS_AES256,
        .cem_algorithm_mac = TLS_SHA1,
    },
    {
        .cem_cipher_name = "AES-128-CBC-HMAC-SHA256",
        .cem_algorithm_enc = TLS_AES128,
        .cem_algorithm_mac = TLS_SHA256,
    },
    {
        .cem_cipher_name = "AES-256-CBC-HMAC-SHA256",
        .cem_algorithm_enc = TLS_AES256,
        .cem_algorithm_mac = TLS_SHA256,
    },
};

#define TLS_CIPHER_ENC_MD_NUM       FC_ARRAY_SIZE(cipher_enc_md)

static const tls_cipher_table *
tls_cipher_info_find(const tls_cipher_table *table,size_t table_cnt,
                        uint32_t mask)
{
    size_t  i = 0;

    for (i = 0; i < table_cnt; i++, table++) { 
        if (table->ct_mask == mask) {
            return table;
        }
    }

    return NULL;
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
    
    return tls_cipher_table_mac[idx].ct_md;
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
tls_load_ciphers(void)
{
    tls_cipher_table  *t = NULL;
    size_t            i = 0;

    for (i = 0, t = tls_cipher_table_cipher; i < TLS_ENC_NUM_IDX; i++, t++) {
        t->ct_cipher = FC_EVP_get_cipherbynid(t->ct_nid);
    }

    for (i = 0, t = tls_cipher_table_mac; i < TLS_MD_NUM_IDX; i++, t++) {
        t->ct_md = FC_EVP_get_digestbynid(t->ct_nid);
        t->ct_secret_size = FC_EVP_MD_size(t->ct_md);
    }

    return 1;
}

int
tls_cipher_get_evp(const TLS_SESSION *s, const FC_EVP_CIPHER **enc,
        const FC_EVP_MD **md, int *mac_pkey_type,
        size_t *mac_secret_size, int use_etm)
{
    const tls_cipher_table  *ct = NULL;
    const tls_cipher_table  *mt = NULL;
    const FC_EVP_CIPHER     *evp = NULL;
    const TLS_CIPHER        *c = NULL;
    int                     i = 0;

    c = s->se_cipher;
    if (c == NULL) {
        FC_LOG("No cipher\n");
        return 0;
    }

    if ((enc == NULL) || (md == NULL)) {
        FC_LOG("Error: enc = %p, md = %p\n", enc, md);
        return 0;
    }

    ct = tls_cipher_info_lookup(tls_cipher_table_cipher, c->cp_algorithm_enc);
    if (ct == NULL) {
        *enc = NULL;
        FC_LOG("Error: cipher info lookup failed!\n");
        return 0;
    }

    *enc = ct->ct_cipher;

    mt = tls_cipher_info_lookup(tls_cipher_table_mac, c->cp_algorithm_mac);
    if (mt == NULL) {
        *md = NULL;
        if (mac_pkey_type != NULL) {
            *mac_pkey_type = NID_undef;
        }
        if (mac_secret_size != NULL) {
            *mac_secret_size = 0;
        }
        if (c->cp_algorithm_mac == TLS_AEAD) {
            mac_pkey_type = NULL;
        }
    } else {
        *md = mt->ct_md;
        *mac_pkey_type = mt->ct_pkey_type;
        if (mac_secret_size != NULL) {
            *mac_secret_size = mt->ct_secret_size;
        }
    }

    if ((*enc != NULL) &&
            (*md != NULL || FC_EVP_CIPHER_flags(*enc) & FC_EVP_CIPH_FLAG_AEAD_CIPHER)
            && (!mac_pkey_type || *mac_pkey_type != NID_undef)) {

        if (use_etm) {
            FC_LOG("Use etm\n");
            return 1;
        }

        for (i = 0; i < TLS_CIPHER_ENC_MD_NUM; i++) {
        FC_LOG("enc = [%lu:%lu], mac = [%lu:%lu], i = %d\n", c->cp_algorithm_enc,
                cipher_enc_md[i].cem_algorithm_enc, c->cp_algorithm_mac,
                cipher_enc_md[i].cem_algorithm_mac, i);
            if (c->cp_algorithm_enc == cipher_enc_md[i].cem_algorithm_enc &&
                c->cp_algorithm_mac == cipher_enc_md[i].cem_algorithm_mac &&
                (evp = FC_EVP_get_cipherbyname(cipher_enc_md[i].cem_cipher_name))) {
                *enc = evp, *md = NULL;
                FC_LOG("Match cipher %s\n", cipher_enc_md[i].cem_cipher_name);
                break;
            }
        }

        FC_LOG("*enc = %p, *md = %p, i = %d\n", *enc, *md, i);
        return 1;
    }

    FC_LOG("Error: *enc = %p, *md = %p\n", *enc, *md);
    return 0;
}

