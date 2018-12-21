#ifndef __FC_INTERNAL_X509_H__
#define __FC_INTERNAL_X509_H__

#include <falcontls/types.h>

#include <openssl/x509.h>

struct fc_x509_t {
    int cert_info;
    int sig_alg; 
    int signature;
    int references;
    void *lock;
};

extern int fc_d2i_x509(FC_X509 *x509, const uint8_t *data, uint32_t len);

#endif
