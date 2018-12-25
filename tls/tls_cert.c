

#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
//#include <falcontls/pem.h>
#include <falcontls/types.h>
#include <fc_log.h>

#include "tls_locl.h"

#if 0
int
tls_verify_cert_chain(TLS *s, FC_STACK_OF(FC_X509) *sk)
{
    return 1;
}

int
FCTLS_use_certificate(TLS *s, FC_X509 *x)
{
    int rv = 0;

    if (x == NULL) {
        return (0);
    }

    return 1;
}

int
FCTLS_CTX_use_certificate(TLS_CTX *ctx, FC_X509 *x)
{
    int rv = 0;

    if (x == NULL) {
        return (0);
    }

    return 1;
}
#endif

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
tls_verify_cert_chain(TLS *s, FC_STACK_OF(FC_X509) *sk)
{
    return 1;
}
