#ifndef __FC_EC_H__
#define __FC_EC_H__

#include <falcontls/evp.h>

enum {
    FC_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1),
    FC_EVP_PKEY_CTRL_EC_PARAM_ENC,
    FC_EVP_PKEY_CTRL_EC_ECDH_COFACTOR,
    FC_EVP_PKEY_CTRL_EC_KDF_TYPE,
    FC_EVP_PKEY_CTRL_EC_KDF_MD,
    FC_EVP_PKEY_CTRL_GET_EC_KDF_MD,
    FC_EVP_PKEY_CTRL_EC_KDF_OUTLEN,
    FC_EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN,
    FC_EVP_PKEY_CTRL_EC_KDF_UKM,
    FC_EVP_PKEY_CTRL_GET_EC_KDF_UKM,
    FC_EVP_PKEY_CTRL_SET1_ID,
    FC_EVP_PKEY_CTRL_GET1_ID,
    FC_EVP_PKEY_CTRL_GET1_ID_LEN,
};

/** Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
        /** the point is encoded as z||x, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    FC_POINT_CONVERSION_COMPRESSED = 2,
        /** the point is encoded as z||x||y, where z is the octet 0x04  */
    FC_POINT_CONVERSION_UNCOMPRESSED = 4,
        /** the point is encoded as z||x||y, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    FC_POINT_CONVERSION_HYBRID = 6
} fc_point_conversion_form_t;

typedef struct ec_method_t FC_EC_METHOD;
typedef struct ec_group_t FC_EC_GROUP;
typedef struct ec_point_t FC_EC_POINT;
typedef struct ecpk_parameters_t FC_ECPKPARAMETERS;
typedef struct ec_parameters_t FC_ECPARAMETERS;

#define FC_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) \
            FC_EVP_PKEY_CTX_ctrl(ctx, FC_EVP_PKEY_EC, \
                    FC_EVP_PKEY_OP_PARAMGEN|FC_EVP_PKEY_OP_KEYGEN, \
                    FC_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL)

extern const FC_EC_GROUP *FC_EC_KEY_get0_group(const FC_EC_KEY *key);
extern fc_point_conversion_form_t FC_EC_KEY_get_conv_form(const FC_EC_KEY *key);
extern const FC_EC_METHOD *FC_EC_GROUP_method_of(const FC_EC_GROUP *group);
extern int FC_EC_METHOD_get_field_type(const FC_EC_METHOD *meth);
extern int FC_EC_GROUP_get_curve_name(const FC_EC_GROUP *group);

#endif
