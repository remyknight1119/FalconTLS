#ifndef __FC_TLS_H__
#define __FC_TLS_H__

#include <falcontls/types.h>
#include <falcontls/safestack.h>

#define FC_TLS_ANY_VERSION                  0x10000
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

/* Extension context codes */ 
/* This extension is only allowed in TLS */
#define FC_TLS_EXT_TLS_ONLY                         0x0001
/* This extension is only allowed in DTLS */
#define FC_TLS_EXT_DTLS_ONLY                        0x0002
/* Some extensions may be allowed in DTLS but we don't implement them for it */
#define FC_TLS_EXT_TLS_IMPLEMENTATION_ONLY          0x0004
/* Most extensions are not defined for SSLv3 but EXT_TYPE_renegotiate is */
#define FC_TLS_EXT_SSL3_ALLOWED                     0x0008
/* Extension is only defined for TLS1.2 and below */
#define FC_TLS_EXT_TLS1_2_AND_BELOW_ONLY            0x0010
/* Extension is only defined for TLS1.3 and above */
#define FC_TLS_EXT_TLS1_3_ONLY                      0x0020
/* Ignore this extension during parsing if we are resuming */
#define FC_TLS_EXT_IGNORE_ON_RESUMPTION             0x0040
#define FC_TLS_EXT_CLIENT_HELLO                     0x0080
/* Really means TLS1.2 or below */
#define FC_TLS_EXT_TLS1_2_SERVER_HELLO              0x0100
#define FC_TLS_EXT_TLS1_3_SERVER_HELLO              0x0200
#define FC_TLS_EXT_TLS1_3_ENCRYPTED_EXTENSIONS      0x0400
#define FC_TLS_EXT_TLS1_3_HELLO_RETRY_REQUEST       0x0800
#define FC_TLS_EXT_TLS1_3_CERTIFICATE               0x1000
#define FC_TLS_EXT_TLS1_3_NEW_SESSION_TICKET        0x2000
#define FC_TLS_EXT_TLS1_3_CERTIFICATE_REQUEST       0x4000

/* What the "other" parameter contains in security callback */
/* Mask for type */
#define TLS_SECOP_OTHER_TYPE    0xffff0000
#define TLS_SECOP_OTHER_NONE    0
#define TLS_SECOP_OTHER_CIPHER  (1 << 16)
#define TLS_SECOP_OTHER_CURVE   (2 << 16)
#define TLS_SECOP_OTHER_DH      (3 << 16)
#define TLS_SECOP_OTHER_PKEY    (4 << 16)
#define TLS_SECOP_OTHER_SIGALG  (5 << 16)
#define TLS_SECOP_OTHER_CERT    (6 << 16)

/* Indicated operation refers to peer key or certificate */
#define TLS_SECOP_PEER          0x1000

/* Values for "op" parameter in security callback */

/* Called to filter ciphers */
/* Ciphers client supports */
#define TLS_SECOP_CIPHER_SUPPORTED      (1 | TLS_SECOP_OTHER_CIPHER)
/* Cipher shared by client/server */
#define TLS_SECOP_CIPHER_SHARED         (2 | TLS_SECOP_OTHER_CIPHER)
/* Sanity check of cipher server selects */
#define TLS_SECOP_CIPHER_CHECK          (3 | TLS_SECOP_OTHER_CIPHER)
/* Curves supported by client */
#define TLS_SECOP_CURVE_SUPPORTED       (4 | TLS_SECOP_OTHER_CURVE)
/* Curves shared by client/server */
#define TLS_SECOP_CURVE_SHARED          (5 | TLS_SECOP_OTHER_CURVE)
/* Sanity check of curve server selects */
#define TLS_SECOP_CURVE_CHECK           (6 | TLS_SECOP_OTHER_CURVE)
/* Temporary DH key */
#define TLS_SECOP_TMP_DH                (7 | TLS_SECOP_OTHER_PKEY)
/* SSL/TLS version */
#define TLS_SECOP_VERSION               (9 | TLS_SECOP_OTHER_NONE)
/* Session tickets */
#define TLS_SECOP_TICKET                (10 | TLS_SECOP_OTHER_NONE)
/* Supported signature algorithms sent to peer */
#define TLS_SECOP_SIGALG_SUPPORTED      (11 | TLS_SECOP_OTHER_SIGALG)
/* Shared signature algorithm */
#define TLS_SECOP_SIGALG_SHARED         (12 | TLS_SECOP_OTHER_SIGALG)
/* Sanity check signature algorithm allowed */
#define TLS_SECOP_SIGALG_CHECK          (13 | TLS_SECOP_OTHER_SIGALG)
/* Used to get mask of supported public key signature algorithms */
#define TLS_SECOP_SIGALG_MASK           (14 | TLS_SECOP_OTHER_SIGALG)
/* Use to see if compression is allowed */
#define TLS_SECOP_COMPRESSION           (15 | TLS_SECOP_OTHER_NONE)
/* EE key in certificate */
#define TLS_SECOP_EE_KEY                (16 | TLS_SECOP_OTHER_CERT)
/* CA key in certificate */
#define TLS_SECOP_CA_KEY                (17 | TLS_SECOP_OTHER_CERT)
/* CA digest algorithm in certificate */
#define TLS_SECOP_CA_MD                 (18 | TLS_SECOP_OTHER_CERT)
/* Peer EE key in certificate */
#define TLS_SECOP_PEER_EE_KEY           (TLS_SECOP_EE_KEY | TLS_SECOP_PEER)
/* Peer CA key in certificate */
#define TLS_SECOP_PEER_CA_KEY           (TLS_SECOP_CA_KEY | TLS_SECOP_PEER)
/* Peer CA digest algorithm in certificate */
#define TLS_SECOP_PEER_CA_MD            (TLS_SECOP_CA_MD | TLS_SECOP_PEER)

typedef int (*TLS_SEC_CB)(const TLS *s, const TLS_CTX *ctx, int op,
                    int bits, int nid, void *other, void *ex);

FC_DEFINE_STACK_OF_CONST(TLS_CIPHER)

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
extern const TLS_METHOD *FCTLS_client_method(void);
extern const TLS_METHOD *FCTLSv1_2_method(void);
extern const TLS_METHOD *FCTLSv1_3_method(void);
extern const TLS_METHOD *FCTLSv1_2_client_method(void);
extern const TLS_METHOD *FCTLSv1_2_server_method(void);
extern const TLS_METHOD *FCTLSv1_3_client_method(void);
extern const TLS_METHOD *FCTLSv1_3_server_method(void);
extern FC_STACK_OF(TLS_CIPHER) *FCTLS_get_ciphers(const TLS *s);
const TLS_METHOD *FCTLS_find_client_method_by_version(int version);
const TLS_METHOD *FCTLS_find_server_method_by_version(int version);

extern TLS_SESSION *TLS_SESSION_new(void);
extern void TLS_SESSION_free(TLS_SESSION *ss);
extern void FCTLS_CTX_set_security_callback(TLS_CTX *ctx, TLS_SEC_CB cb);


#endif
