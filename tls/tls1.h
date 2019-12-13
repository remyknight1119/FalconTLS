#ifndef __TLS1_H__
#define __TLS1_H__

#include "packet_locl.h"

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

#define TLSEXT_SUPPORTED_GROUP_ECCURVE_X25519           29
#define TLSEXT_SUPPORTED_GROUP_ECCURVE_SECP256R1        23
#define TLSEXT_SUPPORTED_GROUP_ECCURVE_X448             30
#define TLSEXT_SUPPORTED_GROUP_ECCURVE_SECP521r1        25
#define TLSEXT_SUPPORTED_GROUP_ECCURVE_SECP384r1        24
#define TLSEXT_SUPPORTED_GROUP_DHE_FFDHE2048            0x100
#define TLSEXT_SUPPORTED_GROUP_DHE_FFDHE3072            0x101
#define TLSEXT_SUPPORTED_GROUP_DHE_FFDHE4096            0x102
#define TLSEXT_SUPPORTED_GROUP_DHE_FFDHE6144            0x103
#define TLSEXT_SUPPORTED_GROUP_DHE_FFDHE8192            0x104

/* ECPointFormat values from RFC4492 */
#define TLSEXT_ECPOINTFORMAT_first                      0
#define TLSEXT_ECPOINTFORMAT_uncompressed               0
#define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime  1
#define TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2  2
#define TLSEXT_ECPOINTFORMAT_last                       2

/* These are used when changing over to a new cipher */
#define TLS_CC_READ            0x001
#define TLS_CC_WRITE           0x002
#define TLS_CC_CLIENT          0x010
#define TLS_CC_SERVER          0x020
#define TLS_CC_EARLY           0x040
#define TLS_CC_HANDSHAKE       0x080
#define TLS_CC_APPLICATION     0x100
#define TLS_CHANGE_CIPHER_CLIENT_WRITE (TLS_CC_CLIENT|TLS_CC_WRITE)
#define TLS_CHANGE_CIPHER_SERVER_READ  (TLS_CC_SERVER|TLS_CC_READ)
#define TLS_CHANGE_CIPHER_CLIENT_READ  (TLS_CC_CLIENT|TLS_CC_READ)
#define TLS_CHANGE_CIPHER_SERVER_WRITE (TLS_CC_SERVER|TLS_CC_WRITE)

int tls_handshake_write(TLS *s);
int tls_set_handshake_header(TLS *s, WPACKET *pkt, int htype);

#endif
