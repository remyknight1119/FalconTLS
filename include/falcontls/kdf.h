#ifndef __FC_KDF_H__
#define __FC_KDF_H__

#include <falcontls/evp.h>

#define FC_EVP_PKEY_CTRL_TLS_MD                   (FC_EVP_PKEY_ALG_CTRL)
#define FC_EVP_PKEY_CTRL_TLS_SECRET               (FC_EVP_PKEY_ALG_CTRL + 1)
#define FC_EVP_PKEY_CTRL_TLS_SEED                 (FC_EVP_PKEY_ALG_CTRL + 2)
#define FC_EVP_PKEY_CTRL_HKDF_MD                  (FC_EVP_PKEY_ALG_CTRL + 3)
#define FC_EVP_PKEY_CTRL_HKDF_SALT                (FC_EVP_PKEY_ALG_CTRL + 4)
#define FC_EVP_PKEY_CTRL_HKDF_KEY                 (FC_EVP_PKEY_ALG_CTRL + 5)
#define FC_EVP_PKEY_CTRL_HKDF_INFO                (FC_EVP_PKEY_ALG_CTRL + 6)
#define FC_EVP_PKEY_CTRL_HKDF_MODE                (FC_EVP_PKEY_ALG_CTRL + 7)
#define FC_EVP_PKEY_CTRL_PASS                     (FC_EVP_PKEY_ALG_CTRL + 8)
#define FC_EVP_PKEY_CTRL_SCRYPT_SALT              (FC_EVP_PKEY_ALG_CTRL + 9)
#define FC_EVP_PKEY_CTRL_SCRYPT_N                 (FC_EVP_PKEY_ALG_CTRL + 10)
#define FC_EVP_PKEY_CTRL_SCRYPT_R                 (FC_EVP_PKEY_ALG_CTRL + 11)
#define FC_EVP_PKEY_CTRL_SCRYPT_P                 (FC_EVP_PKEY_ALG_CTRL + 12)
#define FC_EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES      (FC_EVP_PKEY_ALG_CTRL + 13)

#define FC_EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND 0
#define FC_EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY       1
#define FC_EVP_PKEY_HKDEF_MODE_EXPAND_ONLY        2

#define FC_EVP_PKEY_CTX_set_hkdf_md(pctx, md) \
    FC_EVP_PKEY_CTX_ctrl(pctx, -1, FC_EVP_PKEY_OP_DERIVE, \
            FC_EVP_PKEY_CTRL_HKDF_MD, 0, (void *)(md))
#define FC_EVP_PKEY_CTX_hkdf_mode(pctx, mode) \
    FC_EVP_PKEY_CTX_ctrl(pctx, -1, FC_EVP_PKEY_OP_DERIVE, \
            FC_EVP_PKEY_CTRL_HKDF_MODE, mode, NULL)
#define FC_EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) \
    FC_EVP_PKEY_CTX_ctrl(pctx, -1, FC_EVP_PKEY_OP_DERIVE, \
            FC_EVP_PKEY_CTRL_HKDF_KEY, keylen, (void *)(key))
#define FC_EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) \
    FC_EVP_PKEY_CTX_ctrl(pctx, -1, FC_EVP_PKEY_OP_DERIVE, \
            FC_EVP_PKEY_CTRL_HKDF_INFO, infolen, (void *)(info))
#define FC_EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
    FC_EVP_PKEY_CTX_ctrl(pctx, -1, FC_EVP_PKEY_OP_DERIVE, \
            FC_EVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt))


#endif
