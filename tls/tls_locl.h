#ifndef __FC_TLS_LOCL_H__
#define __FC_TLS_LOCL_H__

#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/types.h>
#include <falcontls/buffer.h>

#include "record_locl.h"
#include "statem.h"
#include "tls1_2.h"

#define TLS_RANDOM_SIZE                     32
#define TLS_SESSION_ID_SIZE                 32
#define TLS_MASTER_SECRET_SIZE              48
#define TLS_HM_HEADER_LENGTH                4

#define TLS_RT_CHANGE_CIPHER_SPEC           20
#define TLS_RT_ALERT                        21
#define TLS_RT_HANDSHAKE                    22
#define TLS_RT_APPLICATION_DATA             23

#define TLS_MT_HELLO_REQUEST            0
#define TLS_MT_CLIENT_HELLO             1
#define TLS_MT_SERVER_HELLO             2
#define TLS_MT_SESSION_TICKET           4
#define TLS_MT_HELLO_RETRY_REQUEST      6
#define TLS_MT_ENCRYPTED_EXTENSIONS     8
#define TLS_MT_CERTIFICATE              11
#define TLS_MT_SERVER_KEY_EXCHANGE      12
#define TLS_MT_CERTIFICATE_REQUEST      13
#define TLS_MT_SERVER_HELLO_DONE        14
#define TLS_MT_CERTIFICATE_VERIFY       15
#define TLS_MT_CLIENT_KEY_EXCHANGE      16
#define TLS_MT_SERVER_CONFIGURATION     17
#define TLS_MT_FINISHED                 20
#define TLS_MT_KEY_UPDATE               24

typedef struct _handshake_t {
    uint8_t     hs_type;
    uint8_t     hs_len[3];
} handshake_t;

typedef struct _random_t {
    uint32_t    rm_unixt_time;
    uint8_t     rm_random_bytes[FC_TLS_RANDOM_BYTES_LEN];
} random_t;

typedef struct _extension_t {
    uint16_t    et_type;
    uint16_t    et_length;
} extension_t;

struct _client_hello_t {
    version_t   ch_version;
    random_t    ch_random;
    uint8_t     ch_session_id_len;
    uint8_t     ch_session_id[0];
} __attribute__ ((__packed__));

typedef struct _client_hello_t client_hello_t;

struct _server_hello_t {
    version_t       sh_version;
    random_t        sh_random;
    uint8_t         sh_session_id_len;
    uint8_t         sh_session_id[0];
} __attribute__ ((__packed__));

typedef struct _server_hello_t server_hello_t;

struct tls_t {
    TLS_STATEM                  tls_statem;
    bool                        tls_server;
    const TLS_METHOD            *tls_method;
    TLS_CTX                     *tls_ctx;
    FC_BIO                      *tls_rbio;
    FC_BIO                      *tls_wbio;
    FC_BUF_MEM                  *tls_init_buf;
    int                         (*tls_handshake_func)(TLS *);
    uint32_t                    tls_version;
    int                         tls_fd;
    RECORD_LAYER                tls_rlayer;
    uint32_t                    tls_max_send_fragment;
};
 
typedef struct tls_enc_method_t {
    int         (*em_enc)(TLS *, TLS_RECORD *, uint32_t, int);
    int         (*em_mac)(TLS *, TLS_RECORD *, uint8_t *, int);
    int         (*em_set_handshake_header)(TLS *s, int type, ulong len);
    int         (*em_do_write)(TLS *s);
    /* Handshake header length */
    uint32_t    em_hhlen;
    uint32_t    em_enc_flags;
} TLS_ENC_METHOD;


struct tls_ctx_t {
    const TLS_METHOD            *sc_method;
    uint32_t                    sc_max_send_fragment;
}; 

struct tls_method_t {
    uint32_t                md_version;
    unsigned                md_flags;
    ulong                   md_mask;
    int                     (*md_tls_new)(TLS *s);
    void                    (*md_tls_clear)(TLS *s);
    void                    (*md_tls_free)(TLS *s);
    int                     (*md_tls_accept)(TLS *s);
    int                     (*md_tls_connect)(TLS *s);
    int                     (*md_tls_read)(TLS *s, void *buf, int len);
    int                     (*md_tls_peek)(TLS *s, void *buf, int len);
    int                     (*md_tls_write)(TLS *s, const void *buf, int len);
    int                     (*md_tls_shutdown)(TLS *s);
    int                     (*md_tls_renegotiate)(TLS *s);
    int                     (*md_tls_renegotiate_check)(TLS *s);
    int                     (*md_tls_read_bytes)(TLS *s, int type, int *recvd_type,
                                uint8_t *buf, int len, int peek); 
    int                     (*md_tls_write_bytes)(TLS *s, int type, 
                                const void *buf_, int len);
    int                     (*md_tls_dispatch_alert)(TLS *s); 
    long                    (*md_tls_ctrl)(TLS *s, int cmd, long larg,
                                void *parg);
    long                    (*md_tls_ctx_ctrl)(TLS_CTX *ctx, int cmd,
                                long larg, void *parg);
    //const TLS_CIPHER        *(*md_get_cipher_by_char)(const uint8_t *ptr);
    //int                     (*md_put_cipher_by_char)(const TLS_CIPHER *cipher,
    //                            uint8_t *ptr);
    int                     (*md_tls_pending) (const TLS *s); 
    int                     (*md_num_ciphers) (void);
    //const TLS_CIPHER        *(*md_get_cipher) (unsigned ncipher);
    long                    (*md_get_timeout)(void);
    const TLS_ENC_METHOD    *md_tls_enc; /* Extra TLS stuff */
    int                     (*md_tls_version) (void);
};

static inline uint32_t get_len_3byte(uint8_t *len)
{
    union {
        uint32_t    len32;
        uint8_t     len8[4];
    } mlen;

    mlen.len8[0] = 0;
    memcpy(&mlen.len8[1], len, 3*sizeof(*len));

    return mlen.len32;
}

TLS_ENC_METHOD const TLSv1_2_enc_data;

#define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, enc_data) \
const TLS_METHOD *func_name(void)  \
        { \
        static const TLS_METHOD func_name##_data= { \
                .md_version = version, \
                .md_flags = flags, \
                .md_mask = mask,  \
                .md_tls_accept = s_accept, \
                .md_tls_connect = s_connect, \
                .md_tls_new = tls1_2_new, \
                .md_tls_clear = tls1_2_clear, \
                .md_tls_free = tls1_2_free, \
                .md_tls_enc = enc_data, \
        }; \
        return &func_name##_data; \
        }


int tls1_2_handshake_write(TLS *s);

#endif
