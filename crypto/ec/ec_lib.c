
#include <falcontls/types.h>
#include <falcontls/ec.h>
#include <falcontls/evp.h>

#include <openssl/ec.h>

const FC_EC_METHOD *
FC_EC_GROUP_method_of(const FC_EC_GROUP *group)
{
    return (const FC_EC_METHOD *)EC_GROUP_method_of((const EC_GROUP *)group);
}

int
FC_EC_METHOD_get_field_type(const FC_EC_METHOD *meth)
{
    return EC_METHOD_get_field_type((const EC_METHOD *)meth);
}

int
FC_EC_GROUP_get_curve_name(const FC_EC_GROUP *group)
{
    return EC_GROUP_get_curve_name((const EC_GROUP *)group);
}
