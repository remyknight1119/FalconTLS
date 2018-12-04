#ifndef __FC_TYPES_H__
#define __FC_TYPES_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef unsigned long ulong;

typedef struct tls_ctx_t TLS_CTX;
typedef struct tls_t TLS;
typedef struct tls_method_t TLS_METHOD;
typedef struct tls_cipher_t TLS_CIPHER;

typedef struct fc_bio_t FC_BIO;
typedef struct fc_bio_method_t FC_BIO_METHOD;
typedef struct fc_buf_mem_t FC_BUF_MEM;
typedef struct fc_evp_peky_t FC_EVP_PKEY;
typedef struct fc_evp_cipher_t FC_EVP_CIPHER;
typedef struct fc_evp_cipher_ctx_t FC_EVP_CIPHER_CTX;
typedef struct fc_evp_md_t FC_EVP_MD;
typedef struct fc_evp_md_ctx_t FC_EVP_MD_CTX;

#endif
