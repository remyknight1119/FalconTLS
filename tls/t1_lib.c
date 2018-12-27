#include <falcontls/types.h>
#include <falcontls/obj_mac.h>
#include <falcontls/evp.h>
#include <falcontls/ec.h>
#include <internal/buffer.h>
#include <fc_lib.h>

#include "packet_locl.h"
#include "tls_locl.h"
#include "tls1.h"
#include "record_locl.h"

/*
 * Table of curve information.
 * Do not delete entries or reorder this array! It is used as a lookup
 * table: the index of each entry is one less than the TLS curve id.
 */
static const TLS_GROUP_INFO nid_list[] = {
    {NID_sect163k1, 80, TLS_CURVE_CHAR2}, /* sect163k1 (1) */
    {NID_sect163r1, 80, TLS_CURVE_CHAR2}, /* sect163r1 (2) */
    {NID_sect163r2, 80, TLS_CURVE_CHAR2}, /* sect163r2 (3) */
    {NID_sect193r1, 80, TLS_CURVE_CHAR2}, /* sect193r1 (4) */
    {NID_sect193r2, 80, TLS_CURVE_CHAR2}, /* sect193r2 (5) */
    {NID_sect233k1, 112, TLS_CURVE_CHAR2}, /* sect233k1 (6) */
    {NID_sect233r1, 112, TLS_CURVE_CHAR2}, /* sect233r1 (7) */
    {NID_sect239k1, 112, TLS_CURVE_CHAR2}, /* sect239k1 (8) */
    {NID_sect283k1, 128, TLS_CURVE_CHAR2}, /* sect283k1 (9) */
    {NID_sect283r1, 128, TLS_CURVE_CHAR2}, /* sect283r1 (10) */
    {NID_sect409k1, 192, TLS_CURVE_CHAR2}, /* sect409k1 (11) */
    {NID_sect409r1, 192, TLS_CURVE_CHAR2}, /* sect409r1 (12) */
    {NID_sect571k1, 256, TLS_CURVE_CHAR2}, /* sect571k1 (13) */
    {NID_sect571r1, 256, TLS_CURVE_CHAR2}, /* sect571r1 (14) */
    {NID_secp160k1, 80, TLS_CURVE_PRIME}, /* secp160k1 (15) */
    {NID_secp160r1, 80, TLS_CURVE_PRIME}, /* secp160r1 (16) */
    {NID_secp160r2, 80, TLS_CURVE_PRIME}, /* secp160r2 (17) */
    {NID_secp192k1, 80, TLS_CURVE_PRIME}, /* secp192k1 (18) */
    {NID_X9_62_prime192v1, 80, TLS_CURVE_PRIME}, /* secp192r1 (19) */
    {NID_secp224k1, 112, TLS_CURVE_PRIME}, /* secp224k1 (20) */
    {NID_secp224r1, 112, TLS_CURVE_PRIME}, /* secp224r1 (21) */
    {NID_secp256k1, 128, TLS_CURVE_PRIME}, /* secp256k1 (22) */
    {NID_X9_62_prime256v1, 128, TLS_CURVE_PRIME}, /* secp256r1 (23) */
    {NID_secp384r1, 192, TLS_CURVE_PRIME}, /* secp384r1 (24) */
    {NID_secp521r1, 256, TLS_CURVE_PRIME}, /* secp521r1 (25) */
    {NID_brainpoolP256r1, 128, TLS_CURVE_PRIME}, /* brainpoolP256r1 (26) */
    {NID_brainpoolP384r1, 192, TLS_CURVE_PRIME}, /* brainpoolP384r1 (27) */
    {NID_brainpoolP512r1, 256, TLS_CURVE_PRIME}, /* brainpool512r1 (28) */
    {FC_EVP_PKEY_X25519, 128, TLS_CURVE_CUSTOM}, /* X25519 (29) */
    {FC_EVP_PKEY_X448, 224, TLS_CURVE_CUSTOM}, /* X448 (30) */
};

static const unsigned char ecformats_default[] = {
    TLSEXT_ECPOINTFORMAT_uncompressed,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2
};

/* The default curves */
static const uint16_t eccurves_default[] = {
    TLSEXT_ECCURVE_X25519,
    TLSEXT_ECCURVE_SECP256R1,
    TLSEXT_ECCURVE_X448,
    TLSEXT_ECCURVE_SECP521r1,
    TLSEXT_ECCURVE_SECP384r1,
};

void
tls_set_record_header(TLS *s, void *record, uint16_t tot_len, int mt)
{
    record_t    *r = NULL;

    r = record;
    r->rd_version.pv_version = FC_HTONS(0x301);
    r->rd_type = mt;
    r->rd_len = FC_HTONS(tot_len);
}

void
tls1_get_formatlist(TLS *s, const unsigned char **pformats,
                         size_t *num_formats)
{
    /*
     * If we have a custom point format list use it otherwise use default
     */
    if (s->tls_ext.ecpointformats) {
        *pformats = s->tls_ext.ecpointformats;
        *num_formats = s->tls_ext.ecpointformats_len;
    } else {
        *pformats = ecformats_default;
        *num_formats = sizeof(ecformats_default);
    }
}

const TLS_GROUP_INFO *
tls1_group_id_lookup(uint16_t group_id)
{
    /* ECC curves from RFC 4492 and RFC 7027 */
    if (group_id < 1 || group_id > FC_ARRAY_SIZE(nid_list)) {
        return NULL;
    }

    return &nid_list[group_id - 1];
}

#if 0
static uint16_t tls1_nid2group_id(int nid)
{
    size_t i;
    for (i = 0; i < OSSL_NELEM(nid_list); i++) {
        if (nid_list[i].nid == nid)
            return (uint16_t)(i + 1);
    }
    return 0;
}
#endif

void
tls1_get_supported_groups(TLS *s, const uint16_t **pgroups,
        size_t *pgroupslen)
{
    if (s->tls_ext.supportedgroups == NULL) {
        *pgroups = eccurves_default;
        *pgroupslen = FC_ARRAY_SIZE(eccurves_default);
    } else {
        *pgroups = s->tls_ext.supportedgroups;
        *pgroupslen = s->tls_ext.supportedgroups_len;
    }
}

/* Return 1 if "id" is in "list" */
static int
tls1_in_list(uint16_t id, const uint16_t *list, size_t listlen)
{
    size_t      i = 0;

    for (i = 0; i < listlen; i++) {
        if (list[i] == id) {
            return 1;
        }
    }

    return 0;
}

/* Check a group id matches preferences */
int
tls1_check_group_id(TLS *s, uint16_t group_id, int check_own_groups)
{
    const uint16_t  *groups = NULL;
    size_t          groups_len = 0;

    if (group_id == 0) {
        return 0;
    }

    if (check_own_groups) {
        /* Check group is one of our preferences */
        tls1_get_supported_groups(s, &groups, &groups_len);
        if (!tls1_in_list(group_id, groups, groups_len)) {
            return 0;
        }
    }

    /* For clients, nothing more to check */
    if (!s->tls_server) {
        return 1;
    }

    /* Check group is one of peers preferences */
    //tls1_get_peer_groups(s, &groups, &groups_len);

    /*
     * RFC 4492 does not require the supported elliptic curves extension
     * so if it is not sent we can just choose any curve.
     * It is invalid to send an empty list in the supported groups
     * extension, so groups_len == 0 always means no extension.
     */
    if (groups_len == 0) {
        return 1;
    }

    return tls1_in_list(group_id, groups, groups_len);
}

/*
 * Generate parameters from a group ID
 */
FC_EVP_PKEY *
tls_generate_param_group(uint16_t id)
{
    FC_EVP_PKEY_CTX         *pctx = NULL;
    FC_EVP_PKEY             *pkey = NULL;
    const TLS_GROUP_INFO    *ginf = NULL;

    ginf = tls1_group_id_lookup(id);
    if (ginf == NULL) {
        goto err;
    }

    if ((ginf->gi_flags & TLS_CURVE_TYPE) == TLS_CURVE_CUSTOM) {
#if 0
        pkey = FC_EVP_PKEY_new();
        if (pkey != NULL && EVP_PKEY_set_type(pkey, ginf->gi_nid))
            return pkey;
        EVP_PKEY_free(pkey);
#endif
        return NULL;
    }

    pctx = FC_EVP_PKEY_CTX_new_id(FC_EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        goto err;
    }
    if (FC_EVP_PKEY_paramgen_init(pctx) <= 0) {
        goto err;
    }
    if (FC_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ginf->gi_nid) <= 0) {
        goto err;
    }
    if (FC_EVP_PKEY_paramgen(pctx, &pkey) <= 0) {
        FC_EVP_PKEY_free(pkey);
        pkey = NULL;
    }

 err:
    FC_EVP_PKEY_CTX_free(pctx);
    return pkey;
}

int
tls12_check_peer_sigalg(TLS *s, uint16_t sig, FC_EVP_PKEY *pkey)
{
    int     pkeyid = 0;
    
    pkeyid = FC_EVP_PKEY_id(pkey);
    if (pkeyid == -1) {
        return -1;
    }

    return 1;
}

