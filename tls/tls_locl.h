#ifndef __FC_TLS_LOCL_H__
#define __FC_TLS_LOCL_H__

#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/types.h>
#include <falcontls/buffer.h>
#include <falcontls/safestack.h>
#include <falcontls/evp.h>

#include "record_locl.h"
#include "packet_locl.h"
#include "statem.h"
#include "tls1_2.h"

#define TLS_RANDOM_SIZE                     32
#define TLS_SESSION_ID_SIZE                 32
#define TLS_MASTER_SECRET_SIZE              48

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

/* ExtensionType values from RFC3546 / RFC4366 / RFC6066 */
#define TLSEXT_TYPE_server_name                 0
#define TLSEXT_TYPE_max_fragment_length         1
#define TLSEXT_TYPE_client_certificate_url      2
#define TLSEXT_TYPE_trusted_ca_keys             3
#define TLSEXT_TYPE_truncated_hmac              4
#define TLSEXT_TYPE_status_request              5
/* ExtensionType values from RFC4681 */
#define TLSEXT_TYPE_user_mapping                6
/* ExtensionType values from RFC5878 */
#define TLSEXT_TYPE_client_authz                7
#define TLSEXT_TYPE_server_authz                8
/* ExtensionType values from RFC6091 */
#define TLSEXT_TYPE_cert_type                   9

/* ExtensionType values from RFC4492 */
/*
 * Prior to TLSv1.3 the supported_groups extension was known as
 * elliptic_curves
 */
#define TLSEXT_TYPE_supported_groups            10
#define TLSEXT_TYPE_elliptic_curves             TLSEXT_TYPE_supported_groups
#define TLSEXT_TYPE_ec_point_formats            11

/* ExtensionType value from RFC5054 */
#define TLSEXT_TYPE_srp                         12

/* ExtensionType values from RFC5246 */
#define TLSEXT_TYPE_signature_algorithms        13

/* ExtensionType value from RFC5764 */
#define TLSEXT_TYPE_use_srtp    14

/* ExtensionType value from RFC5620 */
#define TLSEXT_TYPE_heartbeat   15

/* ExtensionType value from RFC7301 */
#define TLSEXT_TYPE_application_layer_protocol_negotiation 16

/*
 * Extension type for Certificate Transparency
 * https://tools.ietf.org/html/rfc6962#section-3.3.1
 */
#define TLSEXT_TYPE_signed_certificate_timestamp    18

/*
 * ExtensionType value for TLS padding extension.
 * http://tools.ietf.org/html/draft-agl-tls-padding
 */
#define TLSEXT_TYPE_padding     21

/* ExtensionType value from RFC7366 */
#define TLSEXT_TYPE_encrypt_then_mac    22

/* ExtensionType value from RFC7627 */
#define TLSEXT_TYPE_extended_master_secret      23

/* ExtensionType value from RFC4507 */
#define TLSEXT_TYPE_session_ticket              35

/* As defined for TLS1.3 */
#define TLSEXT_TYPE_psk                         41
#define TLSEXT_TYPE_early_data                  42
#define TLSEXT_TYPE_supported_versions          43
#define TLSEXT_TYPE_cookie                      44
#define TLSEXT_TYPE_psk_kex_modes               45
#define TLSEXT_TYPE_certificate_authorities     47
#define TLSEXT_TYPE_post_handshake_auth         49
#define TLSEXT_TYPE_signature_algorithms_cert   50
#define TLSEXT_TYPE_key_share                   51

/* Temporary extension type */
#define TLSEXT_TYPE_renegotiate                 0xff01



#define n2s(c,s)        ((s=(((uint32_t)((c)[0]))<< 8)| \
                             (((uint32_t)((c)[1]))    )),(c)+=2)
#define s2n(s,c)        (((c)[0]=(uint8_t)(((s)>> 8)&0xff), \
                           (c)[1]=(uint8_t)(((s)    )&0xff)),(c)+=2)

#define n2l3(c,l)       ((l =(((ulong)((c)[0]))<<16)| \
                              (((ulong)((c)[1]))<< 8)| \
                              (((ulong)((c)[2]))    )),(c)+=3)

#define l2n3(l,c)       (((c)[0]=(uint8_t)(((l)>>16)&0xff), \
                           (c)[1]=(uint8_t)(((l)>> 8)&0xff), \
                           (c)[2]=(uint8_t)(((l)    )&0xff)),(c)+=3)



struct tls_t {
    TLS_STATEM                  tls_statem;
    bool                        tls_server;
    const TLS_METHOD            *tls_method;
    TLS_CTX                     *tls_ctx;
    FC_BIO                      *tls_rbio;
    FC_BIO                      *tls_wbio;
    FC_BUF_MEM                  *tls_init_buf;
    FC_STACK_OF(TLS_CIPHER)     *tls_cipher_list;
    FC_STACK_OF(TLS_CIPHER)     *tls_cipher_list_by_id;
    int                         (*tls_handshake_func)(TLS *);
    uint16_t                    tls_version;
    int                         tls_fd;
    int                         tls_init_off;
    void                        *tls_init_msg;
    size_t                      tls_init_num;
    RECORD_LAYER                tls_rlayer;
    uint32_t                    tls_max_send_fragment;
    struct {
        size_t                  ecpointformats_len;
        unsigned char           *ecpointformats;
        size_t                  supportedgroups_len;
        uint16_t                *supportedgroups;
        int                     use_etm;
    } tls_ext;
};
 
typedef struct tls_enc_method_t {
    int         (*em_enc)(TLS *, TLS_RECORD *, uint32_t, int);
    int         (*em_mac)(TLS *, TLS_RECORD *, uint8_t *, int);
    int         (*em_set_handshake_header)(TLS *s, WPACKET *pkt, int mt);
    int         (*em_do_write)(TLS *s);
    /* Handshake header length */
    size_t      em_hhlen;
    uint32_t    em_enc_flags;
} TLS_ENC_METHOD;

typedef struct tls_cert_pkey_t {
    //FC_X509                 *cp_x509;
    //FC_EVP_PKEY             *cp_privatekey;
    FC_STACK_OF(FC_X509)    *cp_chain;
} CERT_PKEY;

typedef struct tls_cert_t {
    CERT_PKEY           *ct_key;
    CERT_PKEY           ct_pkeys[FC_EVP_PKEY_NUM];
} CERT;

struct tls_ctx_t {
    const TLS_METHOD            *sc_method;
    CERT                        *sc_cert;
    FC_STACK_OF(TLS_CIPHER)     *sc_cipher_list;
    FC_STACK_OF(TLS_CIPHER)     *sc_cipher_list_by_id;
    uint32_t                    sc_max_send_fragment;
}; 

struct tls_method_t {
    uint16_t                md_version;
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
    const TLS_CIPHER        *(*md_get_cipher_by_char)(const uint8_t *ptr);
    int                     (*md_put_cipher_by_char)(const TLS_CIPHER *cipher,
                                uint8_t *ptr);
    int                     (*md_tls_pending) (const TLS *s); 
    int                     (*md_num_ciphers) (void);
    const TLS_CIPHER        *(*md_get_cipher) (unsigned ncipher);
    long                    (*md_get_timeout)(void);
    const TLS_ENC_METHOD    *md_tls_enc; /* Extra TLS stuff */
    int                     (*md_tls_version) (void);
};

#define TLS_CIPHER_LEN  2

struct tls_cipher_t {
    const char      *cp_name;           /* text name */
    uint32_t        cp_id;                /* id, 4 bytes, first is version */
    uint32_t        cp_algorithm_mkey;    /* key exchange algorithm */
    uint32_t        cp_algorithm_auth;    /* server authentication */
    uint32_t        cp_algorithm_enc;     /* symmetric encryption */
    uint32_t        cp_algorithm_mac;     /* symmetric authentication */
    uint32_t        cp_alg_bits;          /* Number of bits for algorithm */
    int             cp_strength_bits;     /* Number of bits really used */
};

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
            .md_num_ciphers = tls1_2_num_ciphers, \
            .md_get_cipher = tls1_2_get_cipher, \
            .md_get_cipher_by_char = tls1_2_get_cipher_by_char, \
            .md_put_cipher_by_char = tls1_2_put_cipher_by_char, \
            .md_tls_enc = enc_data, \
        }; \
        return &func_name##_data; \
    }


int tls1_2_handshake_write(TLS *s);
int tls_do_write(TLS *s, int type);
void tls_set_record_header(TLS *s, void *record, uint16_t tot_len, int mt);
FC_STACK_OF(TLS_CIPHER) *tls_get_ciphers_by_id(TLS *s);
void tls1_get_formatlist(TLS *s, const unsigned char **pformats,
                         size_t *num_formats);
void tls1_get_supported_groups(TLS *s, const uint16_t **pgroups,
                        size_t *pgroupslen);

#endif
