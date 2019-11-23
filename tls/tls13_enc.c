
#include "tls_locl.h"
#include "tls1.h"
#include "tls1_3.h"
#include "handshake.h"
#include "cipher.h"


/*
* Given the previous secret |prevsecret| and a new input secret |insecret| of
* length |insecretlen|, generate a new secret and store it in the location
* pointed to by |outsecret|. Returns 1 on success  0 on failure.
*/
int tls13_generate_secret(TLS *s, const FC_EVP_MD *md,
        const unsigned char *prevsecret,
        const unsigned char *insecret,
        size_t insecretlen,
        unsigned char *outsecret)
{
    int     ret = 0;
#if 0
    size_t mdlen, prevsecretlen;
    int mdleni;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    static const char derived_secret_label[] = "derived";
    unsigned char preextractsec[EVP_MAX_MD_SIZE];

    if (pctx == NULL) {
        return 0;
    }

    mdleni = EVP_MD_size(md);
    /* Ensure cast to size_t is safe */
    if (!ossl_assert(mdleni >= 0)) {
        return 0;
    }
    mdlen = (size_t)mdleni;

    if (insecret == NULL) {
        insecret = default_zeros;
        insecretlen = mdlen;
    }
    if (prevsecret == NULL) {
        prevsecret = default_zeros;
        prevsecretlen = 0;
    } else {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        unsigned char hash[EVP_MAX_MD_SIZE];

        /* The pre-extract derive step uses a hash of no messages */
        if (mctx == NULL
                || EVP_DigestInit_ex(mctx, md, NULL) <= 0
                || EVP_DigestFinal_ex(mctx, hash, NULL) <= 0) {
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_CTX_free(pctx);
            return 0;
        }
        EVP_MD_CTX_free(mctx);

        /* Generate the pre-extract secret */
        if (!tls13_hkdf_expand(s, md, prevsecret,
                    (unsigned char *)derived_secret_label,
                    sizeof(derived_secret_label) - 1, hash, mdlen,
                    preextractsec, mdlen, 1)) {
            /* SSLfatal() already called */
            EVP_PKEY_CTX_free(pctx);
            return 0;
        }

        prevsecret = preextractsec;
        prevsecretlen = mdlen;
    }

    ret = EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)
        <= 0
        || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
        || EVP_PKEY_CTX_set1_hkdf_key(pctx, insecret, insecretlen) <= 0
        || EVP_PKEY_CTX_set1_hkdf_salt(pctx, prevsecret, prevsecretlen)
        <= 0
        || EVP_PKEY_derive(pctx, outsecret, &mdlen)
        <= 0;

    EVP_PKEY_CTX_free(pctx);
    if (prevsecret == preextractsec)
        OPENSSL_cleanse(preextractsec, mdlen);
#endif
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

    s->tls_session->se_cipher = s->tls_cipher;
    if (!tls_cipher_get_evp(s->tls_session, &c, &hash, NULL, NULL, 0)) {
        return 0;
    }

    s->tls_state.st_new_sym_enc = c;
    s->tls_state.st_new_hash = hash;

    return 1;
}

static const unsigned char client_early_traffic[] = "c e traffic";
static const unsigned char client_handshake_traffic[] = "c hs traffic";
static const unsigned char client_application_traffic[] = "c ap traffic";
static const unsigned char server_handshake_traffic[] = "s hs traffic";
static const unsigned char server_application_traffic[] = "s ap traffic";

int
tls13_change_cipher_state(TLS *s, int which)
{
    TLS_ENC             *enc = NULL;
    const unsigned char *label = NULL;
    unsigned char       *hash = NULL;
    unsigned char       *insecret = NULL;
    unsigned char       *finsecret = NULL;
    unsigned char       hashval[FC_EVP_MAX_MD_SIZE] = {};
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

    if (!s->tls_server && label == client_early_traffic) {
        s->tls_statem.sm_enc_write_state = ENC_WRITE_STATE_WRITE_PLAIN_ALERTS;
    } else {
        s->tls_statem.sm_enc_write_state = ENC_WRITE_STATE_VALID;
    }

    ret = 1;
err:
    return ret;
}
