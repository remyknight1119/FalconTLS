#ifndef __FC_CIPHER_H__
#define __FC_CIPHER_H__

#include <falcontls/types.h>

/* CCM ciphersuites from RFC7251 */
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM            0x0300C0AC
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM            0x0300C0AD
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8          0x0300C0AE
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8          0x0300C0AF

/* ECDH GCM based ciphersuites from RFC5289 */
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     0x0300C02B
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     0x0300C02C
#define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256       0x0300C02F
#define TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384       0x0300C030

/* TLS v1.2 GCM ciphersuites from RFC5288 */
#define TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256         0x0300009E
#define TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384         0x0300009F

/* CCM ciphersuites from RFC6655 */
#define TLS1_CK_DHE_RSA_WITH_AES_128_CCM                0x0300C09E
#define TLS1_CK_DHE_RSA_WITH_AES_256_CCM                0x0300C09F
#define TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8              0x0300C0A2
#define TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8              0x0300C0A3

/* draft-ietf-tls-chacha20-poly1305-03 */
#define TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305         0x0300CCA8
#define TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       0x0300CCA9
#define TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305           0x0300CCAA

/* TLS v1.3 ciphersuites */
#define TLS1_3_CK_AES_128_GCM_SHA256                     0x03001301
#define TLS1_3_CK_AES_256_GCM_SHA384                     0x03001302
#define TLS1_3_CK_CHACHA20_POLY1305_SHA256               0x03001303
#define TLS1_3_CK_AES_128_CCM_SHA256                     0x03001304
#define TLS1_3_CK_AES_128_CCM_8_SHA256                   0x03001305

/* TLS v1.2 GCM ciphersuites from RFC5288 */
#define TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256            "AES128-GCM-SHA256"
#define TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384            "AES256-GCM-SHA384"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256        "DHE-RSA-AES128-GCM-SHA256"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384        "DHE-RSA-AES256-GCM-SHA384"

/* CCM ciphersuites from RFC6655 */
#define TLS1_TXT_RSA_WITH_AES_128_CCM                   "AES128-CCM"
#define TLS1_TXT_RSA_WITH_AES_256_CCM                   "AES256-CCM"
#define TLS1_TXT_RSA_WITH_AES_128_CCM_8                 "AES128-CCM8"
#define TLS1_TXT_RSA_WITH_AES_256_CCM_8                 "AES256-CCM8"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8             "DHE-RSA-AES128-CCM8"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8             "DHE-RSA-AES256-CCM8"
#define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM               "DHE-PSK-AES128-CCM"
#define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM               "DHE-PSK-AES256-CCM"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM               "DHE-RSA-AES128-CCM"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM               "DHE-RSA-AES256-CCM"
#define TLS1_TXT_PSK_WITH_AES_128_CCM_8                 "PSK-AES128-CCM8"
#define TLS1_TXT_PSK_WITH_AES_256_CCM_8                 "PSK-AES256-CCM8"
#define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8             "DHE-PSK-AES128-CCM8"
#define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8             "DHE-PSK-AES256-CCM8"

/* CCM ciphersuites from RFC7251 */

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM       "ECDHE-ECDSA-AES128-CCM"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM       "ECDHE-ECDSA-AES256-CCM"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8     "ECDHE-ECDSA-AES128-CCM8"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8     "ECDHE-ECDSA-AES256-CCM8"

/* ECDH GCM based ciphersuites from RFC5289 */
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    "ECDHE-ECDSA-AES128-GCM-SHA256"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    "ECDHE-ECDSA-AES256-GCM-SHA384"
#define TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256      "ECDHE-RSA-AES128-GCM-SHA256"
#define TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384      "ECDHE-RSA-AES256-GCM-SHA384"

/* draft-ietf-tls-chacha20-poly1305-03 */
#define TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305         "ECDHE-RSA-CHACHA20-POLY1305"
#define TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       "ECDHE-ECDSA-CHACHA20-POLY1305"
#define TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305           "DHE-RSA-CHACHA20-POLY1305"

#define TLS1_3_RFC_AES_128_GCM_SHA256                   "TLS_AES_128_GCM_SHA256"
#define TLS1_3_RFC_AES_256_GCM_SHA384                   "TLS_AES_256_GCM_SHA384"
#define TLS1_3_RFC_CHACHA20_POLY1305_SHA256             "TLS_CHACHA20_POLY1305_SHA256"
#define TLS1_3_RFC_AES_128_CCM_SHA256                   "TLS_AES_128_CCM_SHA256"
#define TLS1_3_RFC_AES_128_CCM_8_SHA256                 "TLS_AES_128_CCM_8_SHA256"

/* Bits for algorithm_mkey (key exchange algorithm) */

#define TLS_kANY                0x00000000U
/* RSA key exchange */
#define TLS_kRSA                0x00000001U
/* tmp DH key no DH cert */
#define TLS_kDHE                0x00000002U
/* ephemeral ECDH */
#define TLS_kECDHE              0x00000004U
/* synonym */
#define TLS_kEECDH              TLS_kECDHE
/* PSK */
#define TLS_kPSK                0x00000008U
/* GOST key exchange */
#define TLS_kGOST               0x00000010U
/* SRP */
#define TLS_kSRP                0x00000020U
#define TLS_kRSAPSK             0x00000040U
#define TLS_kECDHEPSK           0x00000080U
#define TLS_kDHEPSK             0x00000100U

/* all PSK */

#define TLS_PSK     (TLS_kPSK | TLS_kRSAPSK | TLS_kECDHEPSK | TLS_kDHEPSK)

/* Bits for algorithm_auth (server authentication) */

#define TLS_aANY                0x00000000U
/* RSA auth */
#define TLS_aRSA                0x00000001U
/* ECDSA auth*/
#define TLS_aECDSA              0x00000002U

#define TLS_aGOST01             0x00000004U

#define TLS_aGOST12             0x00000008U

#define TLS_aPSK                0x00000010U


/* Bits for algorithm_enc (symmetric encryption) */
#define TLS_AES128              0x00000001U
#define TLS_AES256              0x00000002U
#define TLS_AES128GCM           0x00000004U
#define TLS_AES256GCM           0x00008008U
#define TLS_AES128CCM           0x00000010U
#define TLS_AES256CCM           0x00000020U
#define TLS_AES128CCM8          0x00000040U
#define TLS_AES256CCM8          0x00000080U
#define TLS_CHACHA20POLY1305    0x00000100U

#define TLS_AESGCM              (TLS_AES128GCM | TLS_AES256GCM)
#define TLS_AESCCM              (TLS_AES128CCM | TLS_AES256CCM | TLS_AES128CCM8 | TLS_AES256CCM8)
#define TLS_AES                 (TLS_AES128|TLS_AES256|TLS_AESGCM|TLS_AESCCM)
#define TLS_CHACHA20            (TLS_CHACHA20POLY1305)

#define TLS_MD5                 0x00000001U
#define TLS_SHA1                0x00000002U
#define TLS_GOST94              0x00000004U
#define TLS_GOST89MAC           0x00000008U
#define TLS_SHA256              0x00000010U
#define TLS_SHA384              0x00000020U
/* Not a real MAC, just an indication it is part of cipher */
#define TLS_AEAD                0x00000040U
#define TLS_GOST12_256          0x00000080U
#define TLS_GOST89MAC12         0x00000100U
#define TLS_GOST12_512          0x00000200U


FC_STACK_OF(TLS_CIPHER) *tls_create_cipher_list(const TLS_METHOD *method,
                        FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list_by_id, CERT *c);
const TLS_CIPHER *tls_get_cipher_by_char(TLS *s, const uint8_t *ptr);

#endif
