#ifndef __TLS1_H__
#define __TLS1_H__

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



#endif
