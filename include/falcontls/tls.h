#ifndef __FC_TLS_H__
#define __FC_TLS_H__

#include <falcontls/types.h>

#define FC_TLS1_2_VERSION                   0x0303
#define FC_TLS1_3_VERSION                   0x0304
#define FC_TLS_MAX_VERSION                  FC_TLS1_3_VERSION

#define FC_TLS_MSG_MAX_LEN                  (65535 - 40)
#define FC_TLS_SESSION_ID_LENGTH            32
#define FC_TLS_RANDOM_BYTES_LEN             28

#define FC_TLS_RT_MAX_PLAIN_LENGTH              16384

/* The maximum number of encrypt/decrypt pipelines we can support */
#define FC_TLS_MAX_PIPELINES                    32
#define FC_TLS_RT_MAX_MD_SIZE                   64
#define FC_TLS_RT_MAX_CIPHER_BLOCK_SIZE         16
#define FC_TLS_RT_MAX_ENCRYPTED_OVERHEAD        (256 + FC_TLS_RT_MAX_MD_SIZE)
#define FC_TLS_RT_SEND_MAX_ENCRYPTED_OVERHEAD \
        (FC_TLS_RT_MAX_CIPHER_BLOCK_SIZE + FC_TLS_RT_MAX_MD_SIZE)


extern TLS_CTX *FCTLS_CTX_new(const TLS_METHOD *meth);
extern void FCTLS_CTX_free(TLS_CTX *ctx);
extern TLS *FCTLS_new(TLS_CTX *ctx);
extern void FCTLS_free(TLS *s);
extern int FCTLS_CTX_use_certificate_file(TLS_CTX *ctx,
            const char *file, uint32_t type);
extern int FCTLS_CTX_use_PrivateKey_file(TLS_CTX *ctx, const char *file,
            uint32_t type);
extern int FCTLS_CTX_check_private_key(const TLS_CTX *ctx);
extern int tls_security(const TLS *s, int op, int bits, int nid, void *other);

extern int FCTLS_CTX_check_private_key(const TLS_CTX *ctx);
extern int FCTLS_check_private_key(const TLS *s);
extern int FCTLS_accept(TLS *s);
extern int FCTLS_connect(TLS *s);
extern int FCTLS_set_fd(TLS *s, int fd);
extern int FCTLS_read(TLS *s, void *buf, uint32_t len);
extern int FCTLS_write(TLS *s, const void *buf, uint32_t len);
extern int FCTLS_shutdown(TLS *s);
extern int FCTLS_init(void);
extern void FalconTLS_add_all_algorighms(void);
extern const TLS_METHOD *FCTLS_method(void);

#endif
