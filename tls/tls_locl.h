#ifndef __FC_TLS_LOCL_H__
#define __FC_TLS_LOCL_H__

#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/types.h>
#include <falcontls/buffer.h>
#include <falcontls/safestack.h>
#include <falcontls/evp.h>

#include "record.h"
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

#define TLS_CIPHER_LEN                  2

#define TLS_MT_HELLO_REQUEST            0
#define TLS_MT_CLIENT_HELLO             1
#define TLS_MT_SERVER_HELLO             2
#define TLS_MT_SESSION_TICKET           4
#define TLS_MT_HELLO_RETRY_REQUEST      6
#define TLS_MT_ENCRYPTED_EXTENSIONS     8
#define TLS_MT_CERTIFICATE              11
#define TLS_MT_SERVER_KEY_EXCHANGE      12
#define TLS_MT_CERTIFICATE_REQUEST      13
#define TLS_MT_SERVER_DONE              14
#define TLS_MT_CERTIFICATE_VERIFY       15
#define TLS_MT_CLIENT_KEY_EXCHANGE      16
#define TLS_MT_SERVER_CONFIGURATION     17
#define TLS_MT_FINISHED                 20
#define TLS_MT_KEY_UPDATE               24

#define TLS_MT_CHANGE_CIPHER_SPEC       0x0101

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
#define TLSEXT_TYPE_cryptopro_bug               0xfde8

/* Temporary extension type */
#define TLSEXT_TYPE_renegotiate                 0xff01

#define TLSEXT_TYPE_next_proto_neg              13172

/* Sigalgs values */
#define TLSEXT_SIGALG_ecdsa_secp256r1_sha256                    0x0403
#define TLSEXT_SIGALG_ecdsa_secp384r1_sha384                    0x0503
#define TLSEXT_SIGALG_ecdsa_secp521r1_sha512                    0x0603
#define TLSEXT_SIGALG_ecdsa_sha224                              0x0303
#define TLSEXT_SIGALG_ecdsa_sha1                                0x0203
#define TLSEXT_SIGALG_rsa_pss_rsae_sha256                       0x0804
#define TLSEXT_SIGALG_rsa_pss_rsae_sha384                       0x0805
#define TLSEXT_SIGALG_rsa_pss_rsae_sha512                       0x0806
#define TLSEXT_SIGALG_rsa_pss_pss_sha256                        0x0809
#define TLSEXT_SIGALG_rsa_pss_pss_sha384                        0x080a
#define TLSEXT_SIGALG_rsa_pss_pss_sha512                        0x080b
#define TLSEXT_SIGALG_rsa_pkcs1_sha256                          0x0401
#define TLSEXT_SIGALG_rsa_pkcs1_sha384                          0x0501
#define TLSEXT_SIGALG_rsa_pkcs1_sha512                          0x0601
#define TLSEXT_SIGALG_rsa_pkcs1_sha224                          0x0301
#define TLSEXT_SIGALG_rsa_pkcs1_sha1                            0x0201
#define TLSEXT_SIGALG_dsa_sha256                                0x0402
#define TLSEXT_SIGALG_dsa_sha384                                0x0502
#define TLSEXT_SIGALG_dsa_sha512                                0x0602
#define TLSEXT_SIGALG_dsa_sha224                                0x0302
#define TLSEXT_SIGALG_dsa_sha1                                  0x0202
#define TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256       0xeeee
#define TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512       0xefef
#define TLSEXT_SIGALG_gostr34102001_gostr3411                   0xeded

#define TLSEXT_SIGALG_ed25519                                   0x0807
#define TLSEXT_SIGALG_ed448                                     0x0808

#define TLS_ST_READ_HEADER                      0xF0
#define TLS_ST_READ_BODY                        0xF1
#define TLS_ST_READ_DONE                        0xF2


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
#define TLS_IS_TLS13(s) ((s)->tls_method->md_version >= FC_TLS1_3_VERSION \
        && (s)->tls_method->md_version != FC_TLS_ANY_VERSION)

/*
 * When adding new digest in the ssl_ciph.c and increment SSL_MD_NUM_IDX make
 * sure to update this constant too
 */
enum {
    TLS_MD_MD5_IDX,
    TLS_MD_SHA1_IDX,
    TLS_MD_GOST94_IDX,
    TLS_MD_GOST89MAC_IDX,
    TLS_MD_SHA256_IDX,
    TLS_MD_SHA384_IDX,
    TLS_MD_GOST12_256_IDX,
    TLS_MD_GOST89MAC12_IDX,
    TLS_MD_GOST12_512_IDX,
    TLS_MD_MD5_SHA1_IDX,
    TLS_MD_SHA224_IDX,
    TLS_MD_SHA512_IDX,
    TLS_MAX_DIGEST,
};

/* Bits for algorithm (handshake digests and other extra flags) */

/* Bits 0-7 are handshake MAC */
#define TLS_HANDSHAKE_MAC_MASK          0xFF
#define TLS_HANDSHAKE_MAC_MD5_SHA1      TLS_MD_MD5_SHA1_IDX
#define TLS_HANDSHAKE_MAC_SHA256        TLS_MD_SHA256_IDX
#define TLS_HANDSHAKE_MAC_SHA384        TLS_MD_SHA384_IDX
#define TLS_HANDSHAKE_MAC_GOST94        TLS_MD_GOST94_IDX
#define TLS_HANDSHAKE_MAC_GOST12_256    TLS_MD_GOST12_256_IDX
#define TLS_HANDSHAKE_MAC_GOST12_512    TLS_MD_GOST12_512_IDX
#define TLS_HANDSHAKE_MAC_DEFAULT       TLS_HANDSHAKE_MAC_MD5_SHA1

/* Bits 8-15 bits are PRF */
#define TLS1_PRF_DGST_SHIFT         8
#define TLS1_PRF_SHA1_MD5           (TLS_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA256             (TLS_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA384             (TLS_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_GOST94             (TLS_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_GOST12_256         (TLS_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_GOST12_512         (TLS_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF                    (TLS_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT)


enum {
    TLS_PKEY_RSA,
    TLS_PKEY_RSA_PSS_SIGN,
    TLS_PKEY_DSA_SIGN,
    TLS_PKEY_ECC,
    TLS_PKEY_GOST01,
    TLS_PKEY_GOST12_256,
    TLS_PKEY_GOST12_512,
    TLS_PKEY_ED25519,
    TLS_PKEY_ED448,
    TLS_PKEY_NUM,
};

/*
 * Structure containing table entry of certificate info corresponding to
 * CERT_PKEY entries
 */
typedef struct {
    int         cl_nid; /* NID of pubic key algorithm */
    uint32_t    cl_amask; /* authmask corresponding to key type */
} TLS_CERT_LOOKUP;

/*
 * Structure containing table entry of values associated with the signature
 * algorithms (signature scheme) extension
*/
typedef struct sigalg_lookup_t {
    /* TLS 1.3 signature scheme name */
    const char  *sl_name;
    /* Raw value used in extension */
    uint16_t    sl_sigalg;
    /* NID of hash algorithm or NID_undef if no hash */
    int         sl_hash;
    /* Index of hash algorithm or -1 if no hash algorithm */
    int         sl_hash_idx;
    /* NID of signature algorithm */
    int         sl_sig;
    /* Index of signature algorithm */
    int         sl_sig_idx;
    /* Combined hash and signature NID, if any */
    int         sl_sigandhash;
    /* Required public key curve (ECDSA only) */
    int         sl_curve;
} SIGALG_LOOKUP;


#define TLS1_2_RANDOM_BYTE_LEN      28

typedef struct tls_random_t {
    uint32_t        rm_unixt_time;
    uint8_t         rm_random_bytes[TLS1_2_RANDOM_BYTE_LEN];
} TLS_RANDOM;

typedef struct tls_state_t {
    size_t                  st_message_size;
    int                     st_message_type;
    int                     st_cert_req;
    uint8_t                 *st_ctype;
    size_t                  st_ctype_len;
    const SIGALG_LOOKUP     *st_peer_sigalg;
    uint16_t                *st_peer_sigalgs;
    uint16_t                *st_peer_cert_sigalgs;
    const FC_EVP_CIPHER     *st_new_sym_enc;
    const FC_EVP_MD         *st_new_hash;
    FC_EVP_PKEY             *st_pkey;
    FC_EVP_PKEY             *st_peer_tmp;
    size_t                  st_peer_sigalgslen;
    size_t                  st_peer_cert_sigalgslen;
    uint32_t                st_valid_flags[TLS_PKEY_NUM];
    TLS_RANDOM              st_client_random;
    TLS_RANDOM              st_server_random;
} TLS_STATE;

struct tls_session_t {
    FC_X509             *se_peer;
    const TLS_CIPHER    *se_cipher;
    struct {
        size_t          ecpointformats_len;
        uint8_t         *ecpointformats; /* peer's list */
    } se_ext;
};

typedef struct tls_cert_pkey_t {
    FC_X509                 *cp_x509;
    FC_EVP_PKEY             *cp_privatekey;
    FC_STACK_OF(FC_X509)    *cp_chain;
} CERT_PKEY;

typedef struct tls_cert_t {
    CERT_PKEY   *ct_key;
    CERT_PKEY   ct_pkeys[FC_EVP_PKEY_NUM];
    /* Security callback */
    TLS_SEC_CB   ct_sec_cb;
    void        *ct_sec_ex;
} CERT;

struct tls_t {
    TLS_STATEM                  tls_statem;
    bool                        tls_server;
    unsigned char               tls_early_secret[FC_EVP_MAX_MD_SIZE];
    unsigned char               tls_handshake_secret[FC_EVP_MAX_MD_SIZE];
    const TLS_METHOD            *tls_method;
    TLS_CTX                     *tls_ctx;
    FC_BIO                      *tls_rbio;
    FC_BIO                      *tls_wbio;
    FC_BUF_MEM                  *tls_init_buf;
    FC_STACK_OF(TLS_CIPHER)     *tls_cipher_list;
    FC_STACK_OF(TLS_CIPHER)     *tls_cipher_list_by_id;
    const TLS_CIPHER            *tls_cipher;
    CERT                        *tls_cert;
    int                         (*tls_handshake_func)(TLS *);
    int                         tls_version;
    int                         tls_client_version;
    int                         tls_fd;
    int                         tls_init_off;
    void                        *tls_init_msg;
    size_t                      tls_init_num;
    size_t                      tls_max_pipelines;
    RECORD_LAYER                tls_rlayer;
    TLS_STATE                   tls_state;
    FC_EVP_PKEY                 *tls_peer_key;
    TLS_SESSION                 *tls_session;
    uint32_t                    tls_max_send_fragment;
    enum {TLS_HRR_NONE = 0, TLS_HRR_PENDING, TLS_HRR_COMPLETE}
                                tls_hello_retry_request;
    struct {
        size_t                  ecpointformats_len;
        unsigned char           *ecpointformats;
        size_t                  supportedgroups_len;
        uint16_t                *supportedgroups;
        int                     use_etm;
    } tls_ext;
};

#define TLS_GET_INIT_BUF_DATA(s)    GET_BUF_DATA(s->tls_init_buf)
 
typedef struct tls_enc_method_t {
    int         (*em_enc)(TLS *, TLS_RECORD *, uint32_t, int);
    int         (*em_mac)(TLS *, TLS_RECORD *, uint8_t *, int);
    int         (*em_set_handshake_header)(TLS *s, WPACKET *pkt, int mt);
    int         (*em_setup_key_block)(TLS *);
    int         (*em_change_cipher_state)(TLS *, int);
    int         (*em_do_write)(TLS *);
    /* Handshake header length */
    size_t      em_hhlen;
    uint32_t    em_enc_flags;
} TLS_ENC_METHOD;

#define TLS_ENC_FLAG_EXPLICIT_IV        0x1
/* Uses signature algorithms extension */
#define TLS_ENC_FLAG_SIGALGS            0x2
/* Uses SHA256 default PRF */
#define TLS_ENC_FLAG_SHA256_PRF         0x4
/* Is DTLS */
#define TLS_ENC_FLAG_DTLS               0x8
/*
 * Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2: may
 * apply to others in future.
 */
#define TLS_ENC_FLAG_TLS1_2_CIPHERS     0x10


typedef struct tls_group_info_t {
    int         gi_nid;         /* Curve NID */
    int         gi_secbits;     /* Bits of security (from SP800-57) */
    uint16_t    gi_flags;       /* Flags: currently just group type */
} TLS_GROUP_INFO;

/* flags values */
#define TLS_CURVE_PRIME         0x0
#define TLS_CURVE_CHAR2         0x1
#define TLS_CURVE_CUSTOM        0x2
#define TLS_CURVE_TYPE          0x3 /* Mask for group type */


/*
 * From ECC-TLS draft, used in encoding the curve type in ECParameters
 */
#define EXPLICIT_PRIME_CURVE_TYPE   1
#define EXPLICIT_CHAR2_CURVE_TYPE   2
#define NAMED_CURVE_TYPE            3

struct tls_ctx_t {
    const TLS_METHOD            *sc_method;
    CERT                        *sc_cert;
    FC_STACK_OF(TLS_CIPHER)     *sc_cipher_list;
    FC_STACK_OF(TLS_CIPHER)     *sc_cipher_list_by_id;
    uint32_t                    sc_max_send_fragment;
}; 

struct tls_method_t {
    int                     md_version;
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
                                void *buf, size_t len, size_t *read_bytes);
    int                     (*md_tls_write_bytes)(TLS *s, int type, 
                                const void *buf, size_t len, size_t *written);
    int                     (*md_tls_dispatch_alert)(TLS *s); 
    long                    (*md_tls_ctrl)(TLS *s, int cmd, long larg,
                                void *parg);
    long                    (*md_tls_ctx_ctrl)(TLS_CTX *ctx, int cmd,
                                long larg, void *parg);
    const TLS_CIPHER        *(*md_get_cipher_by_char)(const uint8_t *ptr);
    int                     (*md_put_cipher_by_char)(const TLS_CIPHER *cipher,
                                WPACKET *pkt, size_t *len);
    int                     (*md_tls_pending) (const TLS *s); 
    int                     (*md_num_ciphers) (void);
    const TLS_CIPHER        *(*md_get_cipher) (unsigned ncipher);
    long                    (*md_get_timeout)(void);
    int                     (*md_tls_version) (void);
    const TLS_ENC_METHOD    *md_tls_enc; /* Extra TLS stuff */
};

#define TLS_USE_ENC_FLAG(s, flag)  \
            (s->tls_method->md_tls_enc->em_enc_flags & flag)

#define TLS_USE_SIGALGS(s)      TLS_USE_ENC_FLAG(s, TLS_ENC_FLAG_SIGALGS)

#define TLS_CIPHER_LEN  2

struct tls_cipher_t {
    const char      *cp_name;           /* text name */
    uint32_t        cp_id;                /* id, 4 bytes, first is version */
    uint64_t        cp_algorithm_mkey;    /* key exchange algorithm */
    uint64_t        cp_algorithm_auth;    /* server authentication */
    uint64_t        cp_algorithm_enc;     /* symmetric encryption */
    uint64_t        cp_algorithm_mac;     /* symmetric authentication */
    uint64_t        cp_alg_bits;          /* Number of bits for algorithm */
    uint64_t        cp_algorithm;
    int             cp_min_tls;
    int             cp_max_tls;
    int             cp_strength_bits;     /* Number of bits really used */
};

typedef struct {
    //custom_ext_method *meths;
    size_t  ce_meths_count;
} custom_ext_methods;

typedef struct raw_extension_t {
    /* Raw packet data for the extension */
    PACKET          re_data;
    /* Set to 1 if the extension is present or 0 otherwise */
    int             re_present;
    /* Set to 1 if we have already parsed the extension or 0 otherwise */
    int             re_parsed;
    /* The type of this extension, i.e. a TLSEXT_TYPE_* value */
    unsigned int    re_type;
    /* Track what order extensions are received in (0-based). */
    size_t          re_received_order;
} RAW_EXTENSION;

typedef struct _serverhello_msg_t {
    unsigned int        sm_compression;
    const unsigned char *sm_cipherchars;
    RAW_EXTENSION       *sm_extensions;
    PACKET              sm_session_id;
    PACKET              sm_extpkt;
} SERVERHELLO_MSG;

/*
 * Extension index values NOTE: Any updates to these defines should be mirrored
 * with equivalent updates to ext_defs in extensions.c
 */
typedef enum tlsext_index_en {
    TLSEXT_IDX_renegotiate,
    TLSEXT_IDX_server_name,
    TLSEXT_IDX_max_fragment_length,
    TLSEXT_IDX_srp,
    TLSEXT_IDX_ec_point_formats,
    TLSEXT_IDX_supported_groups,
    TLSEXT_IDX_session_ticket,
    TLSEXT_IDX_status_request,
    TLSEXT_IDX_next_proto_neg,
    TLSEXT_IDX_application_layer_protocol_negotiation,
    TLSEXT_IDX_use_srtp,
    TLSEXT_IDX_encrypt_then_mac,
    TLSEXT_IDX_signed_certificate_timestamp,
    TLSEXT_IDX_extended_master_secret,
    TLSEXT_IDX_signature_algorithms_cert,
    TLSEXT_IDX_post_handshake_auth,
    TLSEXT_IDX_signature_algorithms,
    TLSEXT_IDX_supported_versions,
    TLSEXT_IDX_psk_kex_modes,
    TLSEXT_IDX_key_share,
    TLSEXT_IDX_cookie,
    TLSEXT_IDX_cryptopro_bug,
    TLSEXT_IDX_early_data,
    TLSEXT_IDX_certificate_authorities,
    TLSEXT_IDX_padding,
    TLSEXT_IDX_psk,
    /* Dummy index - must always be the last entry */
    TLSEXT_IDX_num_builtins
} TLSEXT_INDEX;


TLS_ENC_METHOD const TLSv1_2_enc_data;
TLS_ENC_METHOD const TLSv1_3_enc_data;

typedef struct {  
    int                 vi_version;
    const TLS_METHOD    *(*vi_cmeth)(void);
    const TLS_METHOD    *(*vi_smeth)(void);
} version_info;

#define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, num_ciphers, get_cipher, \
                                 get_cipher_by_char, enc_data) \
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
            .md_num_ciphers = num_ciphers, \
            .md_get_cipher = get_cipher, \
            .md_tls_write_bytes = tls_write_bytes, \
            .md_tls_read_bytes = tls1_2_read_bytes, \
            .md_get_cipher_by_char = get_cipher_by_char, \
            .md_put_cipher_by_char = tls_put_cipher_by_char, \
            .md_tls_enc = enc_data, \
        }; \
        return &func_name##_data; \
    }


int tls_undefined_function(TLS *s);
int tls1_2_handshake_write(TLS *s);
int tls12_check_peer_sigalg(TLS *s, uint16_t sig, FC_EVP_PKEY *pkey);
int tls_do_write(TLS *s, int type);
void tls_set_record_header(TLS *s, void *record, uint16_t tot_len, int mt);
FC_STACK_OF(TLS_CIPHER) *tls_get_ciphers_by_id(TLS *s);
void tls1_get_formatlist(TLS *s, const unsigned char **pformats,
                         size_t *num_formats);
void tls1_get_supported_groups(TLS *s, const uint16_t **pgroups,
                        size_t *pgroupslen);
int tls1_check_group_id(TLS *s, uint16_t group_id, int check_own_groups);
FC_EVP_PKEY *tls_generate_param_group(uint16_t id);
FC_EVP_PKEY *tls_generate_pkey_group(TLS *s, uint16_t id);
int tls_verify_cert_chain(TLS *s, FC_STACK_OF(FC_X509) *sk);
int tls_get_new_session(TLS *s, int session);
int tls_cert_lookup_by_nid(int nid, size_t *pidx);
int tls_curve_allowed(TLS *s, uint16_t curve, int op);
int tls1_save_sigalgs(TLS *s, PACKET *pkt, int cert);
int tls1_process_sigalgs(TLS *s);
size_t tls12_get_psigalgs(TLS *s, int sent, const uint16_t **psigs);
int tls12_copy_sigalgs(TLS *s, WPACKET *pkt, const uint16_t *psig, size_t psiglen);
CERT *tls_cert_new(void);
void tls_cert_free(CERT *c);
CERT *tls_cert_dup(CERT *c);
const version_info *tls_find_method_by_version(int version);
FC_EVP_PKEY *tls_generate_pkey(FC_EVP_PKEY *pm);
int tls_derive(TLS *s, FC_EVP_PKEY *privkey, FC_EVP_PKEY *pubkey, int gensecret);
long tls_get_algorithm(TLS *s);
const FC_EVP_MD *tls_md(int idx);
const FC_EVP_MD *tls_handshake_md(TLS *s);
const FC_EVP_MD *tls_prf_md(TLS *s);
const TLS_CIPHER *tls_search_cipher_byid(const TLS_CIPHER *ciphers,
        size_t num, uint32_t id);
int tls_put_cipher_by_char(const TLS_CIPHER *c, WPACKET *pkt, size_t *len);
int tls13_generate_secret(TLS *s, const FC_EVP_MD *md,
        const unsigned char *prevsecret,
        const unsigned char *insecret,
        size_t insecretlen,
        unsigned char *outsecret);
int tls13_generate_handshake_secret(TLS *s, const unsigned char *insecret,
        size_t insecretlen);
int tls13_setup_key_block(TLS *s);
int tls13_change_cipher_state(TLS *s, int which);
int tls_cipher_get_evp(const TLS_SESSION *s, const FC_EVP_CIPHER **enc,
        const FC_EVP_MD **md, int *mac_pkey_type,
        size_t *mac_secret_size, int use_etm);

#endif
