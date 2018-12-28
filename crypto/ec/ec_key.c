
#include <falcontls/types.h>
#include <falcontls/ec.h>
#include <falcontls/evp.h>

#include <openssl/ec.h>

const FC_EC_GROUP *
FC_EC_KEY_get0_group(const FC_EC_KEY *key)
{
    return (const FC_EC_GROUP *)EC_KEY_get0_group((const EC_KEY *)key);
}

fc_point_conversion_form_t
FC_EC_KEY_get_conv_form(const FC_EC_KEY *key)
{
    return (fc_point_conversion_form_t)EC_KEY_get_conv_form((const EC_KEY *)key);
}
