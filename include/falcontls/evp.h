#ifndef __FC_EVP_H__
#define __FC_EVP_H__

#include <falcontls/types.h>
#include <falcontls/objects.h>

#include <openssl/evp.h>

#define FC_EVP_MAX_MD_SIZE              64/* longest known is SHA512 */
#define FC_EVP_MAX_KEY_LENGTH           64
#define FC_EVP_MAX_IV_LENGTH            16
#define FC_EVP_MAX_BLOCK_LENGTH         32

#define FC_EVP_PKEY_NONE            NID_undef
#define FC_EVP_PKEY_RSA             NID_rsaEncryption
#define FC_EVP_PKEY_RSA2            NID_rsa
#define FC_EVP_PKEY_RSA_PSS         NID_rsassaPss
#define FC_EVP_PKEY_DSA             NID_dsa
#define FC_EVP_PKEY_DSA1            NID_dsa_2
#define FC_EVP_PKEY_DSA2            NID_dsaWithSHA
#define FC_EVP_PKEY_DSA3            NID_dsaWithSHA1
#define FC_EVP_PKEY_DSA4            NID_dsaWithSHA1_2
#define FC_EVP_PKEY_DH              NID_dhKeyAgreement
#define FC_EVP_PKEY_DHX             NID_dhpublicnumber
#define FC_EVP_PKEY_EC              NID_X9_62_id_ecPublicKey
#define FC_EVP_PKEY_SM2             NID_sm2
#define FC_EVP_PKEY_HMAC            NID_hmac
#define FC_EVP_PKEY_CMAC            NID_cmac
#define FC_EVP_PKEY_SCRYPT          NID_id_scrypt
#define FC_EVP_PKEY_TLS1_PRF        NID_tls1_prf
#define FC_EVP_PKEY_HKDF            NID_hkdf
#define FC_EVP_PKEY_POLY1305        NID_poly1305
#define FC_EVP_PKEY_SIPHASH         NID_siphash
#define FC_EVP_PKEY_X25519          NID_X25519
#define FC_EVP_PKEY_ED25519         NID_ED25519
#define FC_EVP_PKEY_X448            NID_X448
#define FC_EVP_PKEY_ED448           NID_ED448

#define FC_EVP_PKEY_OP_UNDEFINED           0
#define FC_EVP_PKEY_OP_PARAMGEN            (1<<1)
#define FC_EVP_PKEY_OP_KEYGEN              (1<<2)
#define FC_EVP_PKEY_OP_SIGN                (1<<3)
#define FC_EVP_PKEY_OP_VERIFY              (1<<4)
#define FC_EVP_PKEY_OP_VERIFYRECOVER       (1<<5)
#define FC_EVP_PKEY_OP_SIGNCTX             (1<<6)
#define FC_EVP_PKEY_OP_VERIFYCTX           (1<<7)
#define FC_EVP_PKEY_OP_ENCRYPT             (1<<8)
#define FC_EVP_PKEY_OP_DECRYPT             (1<<9)
#define FC_EVP_PKEY_OP_DERIVE              (1<<10)

#define FC_EVP_CIPH_STREAM_CIPHER          0x0
#define FC_EVP_CIPH_ECB_MODE               0x1
#define FC_EVP_CIPH_CBC_MODE               0x2
#define FC_EVP_CIPH_CFB_MODE               0x3
#define FC_EVP_CIPH_OFB_MODE               0x4
#define FC_EVP_CIPH_CTR_MODE               0x5
#define FC_EVP_CIPH_GCM_MODE               0x6
#define FC_EVP_CIPH_CCM_MODE               0x7
#define FC_EVP_CIPH_XTS_MODE               0x10001
#define FC_EVP_CIPH_WRAP_MODE              0x10002
#define FC_EVP_CIPH_OCB_MODE               0x10003
#define FC_EVP_CIPH_MODE                   0xF0007

/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
#define FC_EVP_CIPH_FLAG_CUSTOM_CIPHER      0x100000
#define FC_EVP_CIPH_FLAG_AEAD_CIPHER        0x200000
#define FC_EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK  0x400000
/* Cipher can handle pipeline operations */
#define FC_EVP_CIPH_FLAG_PIPELINE           0X800000

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
#define FC_EVP_GCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
#define FC_EVP_GCM_TLS_EXPLICIT_IV_LEN                     8
/* Length of tag for TLS */
#define FC_EVP_GCM_TLS_TAG_LEN                             16

/* CCM TLS constants */
/* Length of fixed part of IV derived from PRF */
#define FC_EVP_CCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
#define FC_EVP_CCM_TLS_EXPLICIT_IV_LEN                     8
/* Total length of CCM IV length for TLS */
#define FC_EVP_CCM_TLS_IV_LEN                              12
/* Length of tag for TLS */
#define FC_EVP_CCM_TLS_TAG_LEN                             16
/* Length of CCM8 tag for TLS */
#define FC_EVP_CCM8_TLS_TAG_LEN                            8

/* Length of tag for TLS */
#define FC_EVP_CHACHAPOLY_TLS_TAG_LEN                      16


enum {
    FC_EVP_PKEY_RSA_ENC = 0,
    FC_EVP_PKEY_RSA_SIGN,
    FC_EVP_PKEY_ECC,
    FC_EVP_PKEY_NUM,
};

#define FC_EVP_MD_CTX_size(e)          FC_EVP_MD_size(FC_EVP_MD_CTX_md(e))
#define FC_EVP_MD_CTX_block_size(e)    FC_EVP_MD_block_size(FC_EVP_MD_CTX_md(e))
#define FC_EVP_MD_CTX_type(e)          FC_EVP_MD_type(FC_EVP_MD_CTX_md(e))

#define FC_EVP_PKEY_assign_RSA(pkey,rsa) \
        FC_EVP_PKEY_assign((pkey), FC_EVP_PKEY_RSA, (char *)(rsa))
#define FC_EVP_PKEY_assign_DH(pkey,dh) \
        FC_EVP_PKEY_assign((pkey), FC_EVP_PKEY_DH, (char *)(dh))
#define FC_EVP_PKEY_assign_EC_KEY(pkey,eckey) \
        FC_EVP_PKEY_assign((pkey), FC_EVP_PKEY_EC, (char *)(eckey))

extern int FC_EVP_PKEY_id(const FC_EVP_PKEY *pkey);
extern FC_EVP_PKEY *FC_EVP_PKEY_new(void);
extern void FC_EVP_PKEY_free(FC_EVP_PKEY *pkey);
extern const FC_EVP_CIPHER *
FC_EVP_CIPHER_CTX_cipher(const FC_EVP_CIPHER_CTX *ctx);
extern int FC_EVP_PKEY_missing_parameters(const FC_EVP_PKEY *pkey);
extern ulong FC_EVP_CIPHER_flags(const FC_EVP_CIPHER *cipher);
extern const FC_EVP_MD *FC_EVP_MD_CTX_md(const FC_EVP_MD_CTX *ctx);
extern int FC_EVP_MD_size(const FC_EVP_MD *md);
extern int FC_EVP_CIPHER_key_length(const FC_EVP_CIPHER *cipher);
extern unsigned long FC_EVP_CIPHER_flags(const FC_EVP_CIPHER *cipher);
#define FC_EVP_CIPHER_mode(e)   (FC_EVP_CIPHER_flags(e) & FC_EVP_CIPH_MODE)

extern int FC_EVP_PKEY_assign(FC_EVP_PKEY *pkey, int type, void *key);
extern FC_EVP_PKEY_CTX *FC_EVP_PKEY_CTX_new_id(int id, FC_ENGINE *e);
extern int FC_EVP_PKEY_paramgen_init(FC_EVP_PKEY_CTX *ctx);
extern int FC_EVP_PKEY_CTX_ctrl(FC_EVP_PKEY_CTX *ctx, int keytype, int optype,
            int cmd, int p1, void *p2);
extern int FC_EVP_PKEY_paramgen(FC_EVP_PKEY_CTX *ctx, FC_EVP_PKEY **ppkey);
extern int FC_EVP_PKEY_keygen_init(FC_EVP_PKEY_CTX *ctx);
extern int FC_EVP_PKEY_keygen(FC_EVP_PKEY_CTX *ctx, FC_EVP_PKEY **ppkey);
extern FC_EVP_PKEY_CTX *FC_EVP_PKEY_CTX_new(FC_EVP_PKEY *pkey, FC_ENGINE *e);
extern void FC_EVP_PKEY_CTX_free(FC_EVP_PKEY_CTX *ctx);
extern int FC_EVP_PKEY_set1_tls_encodedpoint(FC_EVP_PKEY *pkey,
            const unsigned char *pt, size_t ptlen);
extern int FC_EVP_PKEY_id(const FC_EVP_PKEY *pkey);
extern FC_EC_KEY *FC_EVP_PKEY_get0_EC_KEY(FC_EVP_PKEY *pkey);
extern int FC_EVP_PKEY_up_ref(FC_EVP_PKEY *pkey);
extern size_t FC_EVP_PKEY_get1_tls_encodedpoint(FC_EVP_PKEY *pkey,
            unsigned char **ppt);
extern int FC_EVP_PKEY_derive_init(FC_EVP_PKEY_CTX *ctx);
extern int FC_EVP_PKEY_derive_set_peer(FC_EVP_PKEY_CTX *ctx, FC_EVP_PKEY *peer);
extern int FC_EVP_PKEY_derive(FC_EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen);
extern const FC_EVP_CIPHER *FC_EVP_get_cipherbynid(int nid);
extern const FC_EVP_MD *FC_EVP_get_digestbynid(int nid);
extern int FC_EVP_MD_size(const FC_EVP_MD *md);
extern FC_EVP_MD_CTX *FC_EVP_MD_CTX_new(void);
extern void FC_EVP_MD_CTX_free(FC_EVP_MD_CTX *ctx);
extern int FC_EVP_MD_CTX_copy_ex(FC_EVP_MD_CTX *out, const FC_EVP_MD_CTX *in);
extern int FC_EVP_DigestFinal_ex(FC_EVP_MD_CTX *ctx, unsigned char *md,
            unsigned int *size);
extern FC_EVP_CIPHER_CTX *FC_EVP_CIPHER_CTX_new(void);
extern int FC_EVP_CIPHER_CTX_reset(FC_EVP_CIPHER_CTX *c);
extern void FC_EVP_CIPHER_CTX_free(FC_EVP_CIPHER_CTX *ctx);
extern int FC_EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
            const unsigned char *key, const unsigned char *iv, int enc);
extern int FC_EVP_DigestInit_ex(FC_EVP_MD_CTX *ctx, const FC_EVP_MD *type,
            FC_ENGINE *impl);
extern int FC_EVP_DigestUpdate(FC_EVP_MD_CTX *ctx, const void *data,
            size_t count);
extern int FC_EVP_CIPHER_iv_length(const FC_EVP_CIPHER *cipher);
extern int FC_EVP_CipherInit_ex(FC_EVP_CIPHER_CTX *ctx, const FC_EVP_CIPHER *cipher,
            FC_ENGINE *impl, const unsigned char *key,
            const unsigned char *iv, int enc);
extern int FC_EVP_CIPHER_CTX_ctrl(FC_EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);



#endif
