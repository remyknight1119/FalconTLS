#include <assert.h>

#include <falcontls/kdf.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "tls1.h"
#include "tls1_3.h"
#include "handshake.h"
#include "cipher.h"

#define TLS13_MAX_LABEL_LEN     249

/* Always filled with zeros */
static const unsigned char default_zeros[EVP_MAX_MD_SIZE];

int
tls13_hkdf_expand(TLS *s, const FC_EVP_MD *md, const unsigned char *secret,
        const unsigned char *label, size_t labellen,
        const unsigned char *data, size_t datalen,
        unsigned char *out, size_t outlen, int fatal)
{
    static const unsigned char label_prefix[] = "tls13 ";
    FC_EVP_PKEY_CTX     *pctx = NULL;
    WPACKET             pkt = {};
    size_t              hkdflabellen = 0;
    size_t              hashlen = 0;
    int                 ret = 0;
    /*
     * 2 bytes for length of derived secret + 1 byte for length of combined
     * prefix and label + bytes for the label itself + 1 byte length of hash
     * + bytes for the hash itself
     */
    unsigned char hkdflabel[sizeof(uint16_t) + sizeof(uint8_t) +
        + (sizeof(label_prefix) - 1) + TLS13_MAX_LABEL_LEN
        + 1 + FC_EVP_MAX_MD_SIZE] = {};

    pctx = FC_EVP_PKEY_CTX_new_id(FC_EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return 0;
    }

    if (labellen > TLS13_MAX_LABEL_LEN) {
        FC_EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    hashlen = FC_EVP_MD_size(md);
    if (!WPACKET_init_static_len(&pkt, hkdflabel, sizeof(hkdflabel), 0)
            || !WPACKET_put_bytes_u16(&pkt, outlen)
            || !WPACKET_start_sub_packet_u8(&pkt)
            || !WPACKET_memcpy(&pkt, label_prefix, sizeof(label_prefix) - 1)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_close(&pkt)
            || !WPACKET_sub_memcpy_u8(&pkt, data, (data == NULL) ? 0 : datalen)
            || !WPACKET_get_total_written(&pkt, &hkdflabellen)
            || !WPACKET_finish(&pkt)) {
        FC_EVP_PKEY_CTX_free(pctx);
        WPACKET_cleanup(&pkt);
        return 0;
    }

    ret = FC_EVP_PKEY_derive_init(pctx) <= 0
        || FC_EVP_PKEY_CTX_hkdf_mode(pctx, FC_EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)
        <= 0
        || FC_EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
        || FC_EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, hashlen) <= 0
        || FC_EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdflabel, hkdflabellen) <= 0
        || FC_EVP_PKEY_derive(pctx, out, &outlen) <= 0;

    FC_EVP_PKEY_CTX_free(pctx);

    return ret == 0;
}

/*
 * Given a |secret| generate a |key| of length |keylen| bytes. Returns 1 on
 * success  0 on failure.
 */
int
tls13_derive_key(TLS *s, const FC_EVP_MD *md, const unsigned char *secret,
        unsigned char *key, size_t keylen)
{
    static const unsigned char keylabel[] = "key";

    return tls13_hkdf_expand(s, md, secret, keylabel, sizeof(keylabel) - 1,
            NULL, 0, key, keylen, 1);
}

int
tls13_derive_iv(TLS *s, const FC_EVP_MD *md, const unsigned char *secret,
        unsigned char *iv, size_t ivlen)
{
    static const unsigned char ivlabel[] = "iv";

    return tls13_hkdf_expand(s, md, secret, ivlabel, sizeof(ivlabel) - 1,
            NULL, 0, iv, ivlen, 1);
}

int
tls13_derive_finishedkey(TLS *s, const FC_EVP_MD *md,
        const unsigned char *secret,
        unsigned char *fin, size_t finlen)
{
    static const unsigned char finishedlabel[] = "finished";

    return tls13_hkdf_expand(s, md, secret, finishedlabel,
            sizeof(finishedlabel) - 1, NULL, 0, fin, finlen, 1);
}

/*
* Given the previous secret |prevsecret| and a new input secret |insecret| of
* length |insecretlen|, generate a new secret and store it in the location
* pointed to by |outsecret|. Returns 1 on success  0 on failure.
*/
int
tls13_generate_secret(TLS *s, const FC_EVP_MD *md,
        const unsigned char *prevsecret,
        const unsigned char *insecret,
        size_t insecretlen,
        unsigned char *outsecret)
{
    FC_EVP_PKEY_CTX     *pctx = NULL;
    static const char   derived_secret_label[] = "derived";
    unsigned char       preextractsec[FC_EVP_MAX_MD_SIZE] = {};
    size_t              mdlen = 0;
    size_t              prevsecretlen = 0;
    int                 mdleni = 0;
    int                 ret = 0;

    pctx = FC_EVP_PKEY_CTX_new_id(FC_EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return 0;
    }

    mdleni = FC_EVP_MD_size(md);
    /* Ensure cast to size_t is safe */
    assert(mdleni >= 0);

    mdlen = (size_t)mdleni;

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        FC_EVP_MD_CTX *mctx = FC_EVP_MD_CTX_new();
        unsigned char hash[FC_EVP_MAX_MD_SIZE];

        /* The pre-extract derive step uses a hash of no messages */
        if (mctx == NULL
                || FC_EVP_DigestInit_ex(mctx, md, NULL) <= 0
                || FC_EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
            FC_EVP_MD_CTX_free(mctx);
            FC_EVP_PKEY_CTX_free(pctx);
            return 0;
        }
        FC_EVP_MD_CTX_free(mctx);

        /* Generate the pre-extract secret */
        if (!tls13_hkdf_expand(s, md, prevsecret,
                    (unsigned char *)derived_secret_label,
                    sizeof(derived_secret_label) - 1, hash, mdlen,
                    preextractsec, mdlen, 1)) {
            /* SSLfatal() already called */
            FC_EVP_PKEY_CTX_free(pctx);
            return 0;
        }

        prevsecret = preextractsec;
        prevsecretlen = mdlen;
    }

    ret = FC_EVP_PKEY_derive_init(pctx) <= 0
        || FC_EVP_PKEY_CTX_hkdf_mode(pctx, FC_EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
        <= 0
        || FC_EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
        || FC_EVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, insecretlen) <= 0
        || FC_EVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen)
        <= 0
        || FC_EVP_PKEY_derive(pctx, outsecret, &mdlen)
        <= 0;

    FC_EVP_PKEY_CTX_free(pctx);
    if (prevsecret == preextractsec) {
        FALCONTLS_free(preextractsec);
    }

    return ret == 0;
}

/*
 * Given an input secret |insecret| of length |insecretlen| generate the
 * handshake secret. This requires the early secret to already have been
 * generated. Returns 1 on success  0 on failure.
 */
int
tls13_generate_handshake_secret(TLS *s, const unsigned char *insecret,
        size_t insecretlen)
{
    /* Calls SSLfatal() if required */
    return tls13_generate_secret(s, tls_handshake_md(s), s->tls_early_secret,
            insecret, insecretlen,
            (unsigned char *)&s->tls_handshake_secret);
}

/*
* There isn't really a key block in TLSv1.3, but we still need this function
* for initialising the cipher and hash. Returns 1 on success or 0 on failure.
*/
int
tls13_setup_key_block(TLS *s)
{
    const FC_EVP_CIPHER     *c = NULL;
    const FC_EVP_MD         *hash = NULL;

    s->tls_session->se_cipher = s->tls_state.st_new_cipher;
    if (!tls_cipher_get_evp(s->tls_session, &c, &hash, NULL, NULL, 0)) {
        return 0;
    }

    s->tls_state.st_new_sym_enc = c;
    s->tls_state.st_new_hash = hash;

    return 1;
}

static int
derive_secret_key_and_iv(TLS *s, int sending, const FC_EVP_MD *md,
        const FC_EVP_CIPHER *ciph,
        const unsigned char *insecret,
        const unsigned char *hash,
        const unsigned char *label,
        size_t labellen, unsigned char *secret,
        unsigned char *iv, FC_EVP_CIPHER_CTX *ciph_ctx)
{
    unsigned char   key[FC_EVP_MAX_KEY_LENGTH] = {};
    size_t          ivlen = 0;
    size_t          keylen = 0;
    size_t          taglen = 0;
    size_t          hashlen = 0;
    int             hashleni = FC_EVP_MD_size(md);

    hashlen = (size_t)hashleni;
    if (!tls13_hkdf_expand(s, md, insecret, label, labellen, hash, hashlen,
                secret, hashlen, 1)) {
        goto err;
    }

    keylen = FC_EVP_CIPHER_key_length(ciph);
    if (FC_EVP_CIPHER_mode(ciph) == FC_EVP_CIPH_CCM_MODE) {
        uint32_t algenc;

        ivlen = FC_EVP_CCM_TLS_IV_LEN;    
        if (s->tls_state.st_new_cipher == NULL) {
            /* We've not selected a cipher yet - we must be doing early data */
            algenc = s->tls_session->se_cipher->cp_algorithm_enc;
        } else {
            algenc = s->tls_state.st_new_cipher->cp_algorithm_enc;
        }
        if (algenc & (TLS_AES128CCM8 | TLS_AES256CCM8)) {
            taglen = FC_EVP_CCM8_TLS_TAG_LEN;
        } else {
            taglen = FC_EVP_CCM_TLS_TAG_LEN;
        }
    } else {
        ivlen = FC_EVP_CIPHER_iv_length(ciph);
        taglen = 0;
    }

    if (!tls13_derive_key(s, md, secret, key, keylen)
            || !tls13_derive_iv(s, md, secret, iv, ivlen)) {
        goto err;
    }

    if (FC_EVP_CipherInit_ex(ciph_ctx, ciph, NULL, NULL, NULL, sending) <= 0
            || !FC_EVP_CIPHER_CTX_ctrl(ciph_ctx, FC_EVP_CTRL_AEAD_SET_IVLEN,
                ivlen, NULL)
            || (taglen != 0 && !FC_EVP_CIPHER_CTX_ctrl(ciph_ctx,
                    FC_EVP_CTRL_AEAD_SET_TAG, taglen, NULL))
            || FC_EVP_CipherInit_ex(ciph_ctx, NULL, NULL, key, NULL, -1) <= 0) {
        goto err;
    }

    return 1;
err:
    FALCONTLS_free(key);
    return 0;
}

static const unsigned char client_early_traffic[] = "c e traffic";
static const unsigned char client_handshake_traffic[] = "c hs traffic";
static const unsigned char client_application_traffic[] = "c ap traffic";
static const unsigned char server_handshake_traffic[] = "s hs traffic";
static const unsigned char server_application_traffic[] = "s ap traffic";
static const unsigned char resumption_master_secret[] = "res master";
static const unsigned char exporter_master_secret[] = "exp master";

int
tls13_change_cipher_state(TLS *s, int which)
{
    TLS_ENC             *enc = NULL;
    const FC_EVP_MD     *md = NULL;
    const FC_EVP_CIPHER *cipher = NULL;
    const unsigned char *label = NULL;
    unsigned char       *hash = NULL;
    unsigned char       *insecret = NULL;
    unsigned char       *finsecret = NULL;
    unsigned char       hashval[FC_EVP_MAX_MD_SIZE] = {};
    unsigned char       secret[FC_EVP_MAX_MD_SIZE] = {};
    size_t              finsecretlen = 0;
    size_t              labellen = 0;
    size_t              hashlen = 0;
    int                 ret = 0;

    hash = hashval;
    if (which & TLS_CC_READ) {
        enc = &s->tls_enc_read;
    } else {
        enc = &s->tls_enc_write;
        s->tls_statem.sm_enc_write_state = ENC_WRITE_STATE_INVALID;
    }

    if (enc->ec_ctx != NULL) {
        FC_EVP_CIPHER_CTX_reset(enc->ec_ctx);
    } else {
        enc->ec_ctx = FC_EVP_CIPHER_CTX_new();
        if (enc->ec_ctx == NULL) {
            FC_LOG("New EVP_CIPHER_CTX failed\n");
            goto err;
        }
    }

    if (((which & TLS_CC_CLIENT) && (which & TLS_CC_WRITE)) ||
            ((which & TLS_CC_SERVER) && (which & TLS_CC_READ))) {
        if (which & TLS_CC_HANDSHAKE) {
            insecret = s->tls_handshake_secret;
            finsecret = s->tls_client_finished_secret;
            finsecretlen = FC_EVP_MD_size(tls_handshake_md(s));
            label = client_handshake_traffic;
            labellen = sizeof(client_handshake_traffic) - 1;
            hash = s->tls_handshake_traffic_hash;
        } else {
            insecret = s->tls_master_secret;
            label = client_application_traffic;
            labellen = sizeof(client_application_traffic) - 1;
            hash = s->tls_server_finished_hash;
        }
    } else {
        if (which & TLS_CC_HANDSHAKE) {
            insecret = s->tls_handshake_secret;
            finsecret = s->tls_server_finished_secret;
            finsecretlen = FC_EVP_MD_size(tls_handshake_md(s));
            label = server_handshake_traffic;
            labellen = sizeof(server_handshake_traffic) - 1;
        } else {
            insecret = s->tls_master_secret;
            label = server_application_traffic;
            labellen = sizeof(server_application_traffic) - 1;
        }
    }

    if (!(which & TLS_CC_EARLY)) {
        md = tls_handshake_md(s);
        cipher = s->tls_state.st_new_sym_enc;
        if (!tls_digest_cached_records(s, 1) ||
                !tls_handshake_hash(s, hashval, sizeof(hashval), &hashlen)) {
            FC_LOG("Digest or handshake hash failed\n");
            goto err;
        }
    }

    /*
     * Save the hash of handshakes up to now for use when we calculate the
     * client application traffic secret
     */
    if (label == server_application_traffic) {
        memcpy(s->tls_server_finished_hash, hashval, hashlen);
    }

    if (label == server_handshake_traffic) {
        memcpy(s->tls_handshake_traffic_hash, hashval, hashlen);
    }

    if (label == client_application_traffic) {
        if (!tls13_hkdf_expand(s, tls_handshake_md(s), insecret,
                    resumption_master_secret,
                    sizeof(resumption_master_secret) - 1,
                    hashval, hashlen, s->tls_resumption_master_secret,
                    hashlen, 1)) {
            FC_LOG("hkdf expand failed\n");
            goto err;
        }
    }

    if (!derive_secret_key_and_iv(s, which & TLS_CC_WRITE, md, cipher,
                insecret, hash, label, labellen, secret, enc->ec_iv,
                enc->ec_ctx)) {
        FC_LOG("Derive secret key and iv failed\n");
        goto err;
    }

    if (label == server_application_traffic) {
        memcpy(s->tls_server_app_traffic_secret, secret, hashlen);
        if (!tls13_hkdf_expand(s, tls_handshake_md(s), insecret,
                    exporter_master_secret,
                    sizeof(exporter_master_secret) - 1,
                    hash, hashlen, s->tls_exporter_master_secret,
                    hashlen, 1)) {
            FC_LOG("hkdf expand failed\n");
            goto err;
        }
    }

    if (finsecret != NULL
            && !tls13_derive_finishedkey(s, tls_handshake_md(s), secret,
                finsecret, finsecretlen)) {
        FC_LOG("Derive finished key failed\n");
        goto err;
    }

    if (!s->tls_server && label == client_early_traffic) {
        s->tls_statem.sm_enc_write_state = ENC_WRITE_STATE_WRITE_PLAIN_ALERTS;
    } else {
        s->tls_statem.sm_enc_write_state = ENC_WRITE_STATE_VALID;
    }

    ret = 1;
err:
    return ret;
}

int
tls1_3_enc(TLS *s, TLS_RECORD *recs, size_t n_recs, int sending)
{
    TLS_ENC             *enc = NULL;
    TLS_RECORD          *rec = NULL;

    rec = &recs[0];
    if (sending) {
        enc = &s->tls_enc_write;
    } else {
        enc = &s->tls_enc_read;
    }

    if (enc->ec_ctx == NULL || rec->rd_type == TLS_RT_ALERT) {
        memmove(rec->rd_data, rec->rd_input, rec->rd_length);
        rec->rd_input = rec->rd_data;
        FC_LOG("Plaintext\n");
        return 1;
    }

        FC_LOG("Ciphertext\n");
    return 1;
}



