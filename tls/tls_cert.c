

#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
//#include <falcontls/pem.h>
#include <falcontls/types.h>
#include <falcontls/evp.h>
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

int
FCTLS_CTX_use_certificate(TLS_CTX *ctx, FC_X509 *x)
{
    //int rv = 0;

    if (x == NULL) {
        return (0);
    }

    return 1;
}

int
FCTLS_CTX_use_certificate_file(TLS_CTX *ctx, const char *file, 
        uint32_t type)
{
#if 0
    FC_BIO      *in = NULL;
    FC_X509     *x = NULL;
    int         ret = 0;
    
    in = FC_BIO_new(FC_BIO_s_file());
    if (in == NULL) {
        goto end;
    }

    if (FC_BIO_read_filename(in, file) <= 0) {
        goto end;
    }

    if (type == FC_X509_FILETYPE_ASN1) {
    } else if (type == FC_X509_FILETYPE_PEM) {
        x = FC_PEM_read_bio_X509(in, NULL, NULL, NULL); 
    } else {
        goto end;
    }

    ret = FCTLS_CTX_use_certificate(ctx, x);
    FC_X509_free(x);
end:
    FC_BIO_free(in);
    return ret;
#endif
    return 1;
}

#if 0
int
FCTLS_CTX_use_PrivateKey(TLS_CTX *ctx, FC_EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        return (0);
    }

    //return (tls_set_pkey(ctx->sc_cert, pkey));
    return 1;
}
#endif

int
FCTLS_CTX_use_PrivateKey_file(TLS_CTX *ctx, const char *file, 
        uint32_t type)
{
#if 0
    FC_BIO      *in = NULL;
    FC_EVP_PKEY *pkey = NULL;
#endif
    int         ret = 1;
    
#if 0
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
#endif
    return ret;
}

int
tls_security(const TLS *s, int op, int bits, int nid, void *other)
{
    return 0;
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


