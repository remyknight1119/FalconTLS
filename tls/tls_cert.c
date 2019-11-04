

#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <falcontls/pem.h>
#include <falcontls/types.h>
#include <falcontls/evp.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "cipher.h"

static const TLS_CERT_LOOKUP tls_cert_info [] = {
    {
        .cl_nid = FC_EVP_PKEY_RSA,
        .cl_amask = TLS_aRSA,
    }, /* TLS_PKEY_RSA */
    {
        .cl_nid = FC_EVP_PKEY_RSA_PSS,
        .cl_amask = TLS_aRSA,
    }, /* TLS_PKEY_RSA_PSS_SIGN */
    {
        .cl_nid = FC_EVP_PKEY_EC,
        .cl_amask = TLS_aECDSA,
    }, /* TLS_PKEY_ECC */
    {
        .cl_nid = NID_id_GostR3410_2001,
        .cl_amask = TLS_aGOST01,
    }, /* TLS_PKEY_GOST01 */
    {
        .cl_nid = NID_id_GostR3410_2012_256,
        .cl_amask = TLS_aGOST12,
    }, /* TLS_PKEY_GOST12_256 */
    {
        .cl_nid = NID_id_GostR3410_2012_512,
        .cl_amask = TLS_aGOST12,
    }, /* TLS_PKEY_GOST12_512 */
    {
        .cl_nid = FC_EVP_PKEY_ED25519,
        .cl_amask = TLS_aECDSA,
    }, /* TLS_PKEY_ED25519 */
    {
        .cl_nid = FC_EVP_PKEY_ED448,
        .cl_amask = TLS_aECDSA,
    }, /* TLS_PKEY_ED448 */
};

static int
tls_security_default_callback(const TLS *s, const TLS_CTX *ctx, int op,
                int bits, int nid, void *other, void *ex)
{
    return 1;
}

CERT *
tls_cert_new(void)
{
    CERT    *ret = NULL;
    
    ret = FALCONTLS_calloc(sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }

    ret->ct_key = &(ret->ct_pkeys[TLS_PKEY_RSA]);
    ret->ct_sec_cb = tls_security_default_callback;
    ret->ct_sec_ex = NULL;
#if 0
    ret->sec_level = OPENSSL_TLS_SECURITY_LEVEL;
    ret->ct_references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        SSLerr(SSL_F_SSL_CERT_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }
#endif

    return ret;
}

void
tls_cert_free(CERT *c)
{
    //int i;

    if (c == NULL) {
        return;
    }
#if 0
    CRYPTO_DOWN_REF(&c->references, &i, c->lock);
    REF_PRINT_COUNT("CERT", c);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    EVP_PKEY_free(c->dh_tmp);

    ssl_cert_clear_certs(c);
    OPENSSL_free(c->conf_sigalgs);
    OPENSSL_free(c->client_sigalgs);
    OPENSSL_free(c->shared_sigalgs);
    OPENSSL_free(c->ctype);
    X509_STORE_free(c->verify_store);
    X509_STORE_free(c->chain_store);
    custom_exts_free(&c->custext);
    OPENSSL_free(c->psk_identity_hint);
    CRYPTO_THREAD_lock_free(c->lock);
#endif
    FALCONTLS_free(c);
}

CERT *
tls_cert_dup(CERT *cert)
{
    CERT *ret = FALCONTLS_calloc(sizeof(*ret));

    if (ret == NULL) {   
        return NULL;     
    }

    memcpy(ret, cert, sizeof(*cert));

    return ret;
}

int
tls_cert_lookup_by_nid(int nid, size_t *pidx)
{
    size_t  i = 0;

    for (i = 0; i < FC_ARRAY_SIZE(tls_cert_info); i++) {
        if (tls_cert_info[i].cl_nid == nid) {
            *pidx = i;
            return 1;
        }
    }

    return 0;
}

const TLS_CERT_LOOKUP *
tls_cert_lookup_by_pkey(const FC_EVP_PKEY *pk, size_t *pidx)
{
    size_t  tmpidx = 0;
    int     nid = FC_EVP_PKEY_id(pk);

    if (nid == NID_undef) {
        return NULL;
    }

    if (!tls_cert_lookup_by_nid(nid, &tmpidx)) {
        return NULL;
    }

    if (pidx != NULL) {
        *pidx = tmpidx;
    }

    return &tls_cert_info[tmpidx];
}

int
tls_verify_cert_chain(TLS *s, FC_STACK_OF(FC_X509) *sk)
{
    return 1;
}

int
FCTLS_use_certificate(TLS *s, FC_X509 *x)
{
    //int rv = 0;

    if (x == NULL) {
        return (0);
    }

    return 1;
}

static int
tls_set_cert(CERT *c, FC_X509 *x)
{
    FC_EVP_PKEY     *pkey = NULL;
    size_t          i = 0;

    pkey = FC_X509_get0_pubkey(x);
    if (pkey == NULL) {
        return 0;
    }

    if (tls_cert_lookup_by_pkey(pkey, &i) == NULL) {
        return 0;
    }

#if 0
    if (i == T:S_PKEY_ECC && !EC_KEY_can_sign(FC_EVP_PKEY_get0_EC_KEY(pkey))) {
        return 0;
    }
#endif

    if (c->ct_pkeys[i].cp_privatekey != NULL) {
    }

    FC_X509_free(c->ct_pkeys[i].cp_x509);
    FC_X509_up_ref(x);
    c->ct_pkeys[i].cp_x509 = x;
    c->ct_key = &(c->ct_pkeys[i]);

    return 1;
}

int
FCTLS_CTX_use_certificate(TLS_CTX *ctx, FC_X509 *x)
{
    return tls_set_cert(ctx->sc_cert, x);
}

int
FCTLS_CTX_use_certificate_file(TLS_CTX *ctx, const char *file, 
        uint32_t type)
{
    FC_BIO      *in = NULL;
    FC_X509     *x = NULL;
    int         ret = 0;
    
    in = FC_BIO_new(FC_BIO_s_file());
    if (in == NULL) {
        FC_LOG("Open %s failed\n", file);
        goto end;
    }

    if (FC_BIO_read_filename(in, file) <= 0) {
        FC_LOG("Read %s failed\n", file);
        goto end;
    }

    if (type == FC_X509_FILETYPE_ASN1) {
    } else if (type == FC_X509_FILETYPE_PEM) {
        x = FC_PEM_read_bio_X509(in, NULL, NULL, NULL); 
    } else {
        goto end;
    }

    ret = FCTLS_CTX_use_certificate(ctx, x);
    FC_LOG("ret = %d, x= %p\n", ret, x);
    FC_X509_free(x);
end:
    FC_BIO_free(in);
    return ret;
}

static int
tls_set_pkey(CERT *c, FC_EVP_PKEY *pkey)
{
    size_t          i = 0;

    if (tls_cert_lookup_by_pkey(pkey, &i) == NULL) {
        return 0;
    }

    if (c->ct_pkeys[i].cp_privatekey != NULL) {
    }


    FC_EVP_PKEY_free(c->ct_pkeys[i].cp_privatekey);
    FC_EVP_PKEY_up_ref(pkey);
    c->ct_pkeys[i].cp_privatekey = pkey;
    c->ct_key = &c->ct_pkeys[i];
    return 1;
}

int
FCTLS_CTX_use_PrivateKey(TLS_CTX *ctx, FC_EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        return (0);
    }

    return (tls_set_pkey(ctx->sc_cert, pkey));
}

int
FCTLS_CTX_use_PrivateKey_file(TLS_CTX *ctx, const char *file, 
        uint32_t type)
{
    FC_BIO      *in = NULL;
    FC_EVP_PKEY *pkey = NULL;
    int         ret = 1;
    
    in = FC_BIO_new(FC_BIO_s_file());
    if (in == NULL) {
        goto end;
    }

    if (FC_BIO_read_filename(in, file) <= 0) {
        goto end;
    }

    if (type == FC_X509_FILETYPE_ASN1) {
    } else if (type == FC_X509_FILETYPE_PEM) {
        pkey = FC_PEM_read_bio_PrivateKey(in, NULL, NULL, NULL); 
    } else {
        goto end;
    }

    ret = FCTLS_CTX_use_PrivateKey(ctx, pkey);
    FC_EVP_PKEY_free(pkey);
end:
    FC_BIO_free(in);
    return ret;
}

int
tls_security(const TLS *s, int op, int bits, int nid, void *other)
{
    return s->tls_cert->ct_sec_cb(s, NULL, op, bits, nid, other,
                    s->tls_cert->ct_sec_ex);
}


