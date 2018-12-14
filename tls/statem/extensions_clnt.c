

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
tls_parse_stoc_ec_pt_formats(TLS *s, PACKET *pkt, uint32_t context, FC_X509 *x,
                    size_t chainidx)
{
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


