
#include <fc_log.h>

#include "tls_locl.h"
#include "cipher.h"
#include "statem_locl.h"
#include "packet_locl.h"

int
tls_parse_stoc_etm(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_stoc_ems(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_stoc_sig_algs(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_stoc_ec_pt_formats(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    PACKET      ecptformatlist = {};
    //size_t      ecpointformats_len = 0;

    //FC_LOG("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n");
    if (!PACKET_as_length_prefixed_1(pkt, &ecptformatlist)) {
        return 0;
    }

    return 1;
}

int
tls_parse_stoc_supported_versions(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    return 1;
}

int
tls_parse_stoc_key_share(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
    FC_EVP_PKEY     *ckey = NULL;
    FC_EVP_PKEY     *skey = NULL;
    PACKET          encoded_pt = {};
    unsigned int    group_id = 0;

    if (!PACKET_get_net_2(pkt, &group_id)) {
        return 0;
    }

    if (!PACKET_as_length_prefixed_2(pkt, &encoded_pt)
            || PACKET_remaining(&encoded_pt) == 0) {
        return 0;
    }

    ckey = s->tls_state.st_pkey;
    skey = tls_generate_pkey(ckey);
    if (skey == NULL) {
        return 0;
    }

    if (!FC_EVP_PKEY_set1_tls_encodedpoint(skey, PACKET_data(&encoded_pt),
                PACKET_remaining(&encoded_pt))) {
        FC_EVP_PKEY_free(skey);
        return 0;
    }

    if (tls_derive(s, ckey, skey, 1) == 0) {
        FC_EVP_PKEY_free(skey);
        return 0;
    }

    s->tls_state.st_peer_tmp = skey; 
    return 1;
}


EXT_RETURN
tls_construct_ctos_etm(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_encrypt_then_mac)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_ctos_ems(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_extended_master_secret)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_ctos_sig_algs(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    const uint16_t *salg = NULL;
    size_t salglen;

    salglen = tls12_get_psigalgs(s, 1, &salg);
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signature_algorithms)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !tls12_copy_sigalgs(s, pkt, salg, salglen)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static int
use_ecc(TLS *s)
{
    FC_STACK_OF(TLS_CIPHER)     *cipher_stack = NULL;
    int                         i = 0;
    int                         end = 0;
    unsigned long               alg_k = 0;
    unsigned long               alg_a = 0;

    /* See if we support any ECC ciphersuites */

    cipher_stack = FCTLS_get_ciphers(s);
    end = sk_TLS_CIPHER_num(cipher_stack);
    for (i = 0; i < end; i++) {
        const TLS_CIPHER    *c = sk_TLS_CIPHER_value(cipher_stack, i);
        alg_k = c->cp_algorithm_mkey;
        alg_a = c->cp_algorithm_auth;
        if ((alg_k & (TLS_kECDHE /*| TLS_kECDHEPSK*/))
                || (alg_a & TLS_aECDSA)) {
            return 1;
        }
    }

    return 0;
}


EXT_RETURN
tls_construct_ctos_ec_pt_formats(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    const unsigned char *pformats = NULL;
    size_t              num_formats = 0;

    if (!use_ecc(s)) {
        return EXT_RETURN_NOT_SENT;
    }

    /* Add TLS extension ECPointFormats to the ClientHello message */
    tls1_get_formatlist(s, &pformats, &num_formats);

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ec_point_formats) ||
            !WPACKET_put_bytes_u16(pkt, num_formats + 1) ||
            !WPACKET_put_bytes_u8(pkt, num_formats) ||
            !WPACKET_memcpy(pkt, pformats, num_formats)) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_ctos_supported_groups(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    const uint16_t  *pgroups = NULL;
    size_t          num_groups = 0;
    size_t          i = 0;

    if (!use_ecc(s)) {
        return EXT_RETURN_NOT_SENT;
    }

    tls1_get_supported_groups(s, &pgroups, &num_groups);

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_groups) ||
            !WPACKET_put_bytes_u16(pkt, 2*(num_groups + 1)) ||
            !WPACKET_put_bytes_u16(pkt, 2*num_groups)) {
        return EXT_RETURN_FAIL;
    }

    for (i = 0; i < num_groups; i++) {
        uint16_t ctmp = pgroups[i];
        if (!WPACKET_put_bytes_u16(pkt, ctmp)) {
            return EXT_RETURN_FAIL;
        }
    }
    
    return EXT_RETURN_SENT;
}

EXT_RETURN
tls_construct_ctos_supported_versions(TLS *s, WPACKET *pkt, uint32_t context,
                    FC_X509 *x, size_t chainidx)
{
    int     currv = 0;
    int     min_version = 0;
    int     max_version = 0;
    int     reason = 0;

    reason = tls_get_min_max_version(s, &min_version, &max_version);
    if (reason != 0) {
        return EXT_RETURN_FAIL;
    }

    if (max_version < FC_TLS1_3_VERSION) {
        return EXT_RETURN_NOT_SENT;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_supported_versions)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u8(pkt)) {
        return EXT_RETURN_FAIL;
    }

    for (currv = max_version; currv >= min_version; currv--) {
        if (!WPACKET_put_bytes_u16(pkt, currv)) {
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static int
add_key_share(TLS *s, WPACKET *pkt, unsigned int curve_id)
{
    FC_EVP_PKEY     *key_share_key = NULL;
    unsigned char   *encoded_point = NULL;
    size_t          encodedlen = 0;

    key_share_key = tls_generate_pkey_group(s, curve_id);
    if (key_share_key == NULL) {
        return 0;
    }

    encodedlen = FC_EVP_PKEY_get1_tls_encodedpoint(key_share_key,
            &encoded_point);
    if (encodedlen == 0) {
        goto err;
    }

    if (!WPACKET_put_bytes_u16(pkt, curve_id) ||
            !WPACKET_sub_memcpy_u16(pkt, encoded_point, encodedlen)) {
        goto err;
    }

    s->tls_state.st_pkey = key_share_key;
    FALCONTLS_free(encoded_point);
    return 1;
err:
    FALCONTLS_free(encoded_point);
    return 0;
}

EXT_RETURN
tls_construct_ctos_key_share(TLS *s, WPACKET *pkt, uint32_t context,
        FC_X509 *x, size_t chainidx)
{
    size_t i, num_groups = 0;
    const uint16_t *pgroups = NULL;
    uint16_t curve_id = 0;

    /* key_share extension */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_key_share)
            /* Extension data sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)
            /* KeyShare list sub-packet */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        return EXT_RETURN_FAIL;
    }

    tls1_get_supported_groups(s, &pgroups, &num_groups);

    /*
     * TODO(TLS1.3): Make the number of key_shares sent configurable. For
     * now, just send one
     */
    for (i = 0; i < num_groups; i++) {
        if (!tls_curve_allowed(s, pgroups[i], TLS_SECOP_CURVE_SUPPORTED)) {
            continue;
        }
        curve_id = pgroups[i];
        break;
    }

    if (curve_id == 0) {
        return EXT_RETURN_FAIL;
    }

    if (!add_key_share(s, pkt, curve_id)) {
        return EXT_RETURN_FAIL;
    }

    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        return EXT_RETURN_FAIL;
    }
    return EXT_RETURN_SENT;
}

