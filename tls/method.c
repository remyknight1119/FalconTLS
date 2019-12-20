
#include <falcontls/tls.h>
#include "statem.h"
#include "tls_locl.h"
#include "tls1_3.h"

IMPLEMENT_tls_meth_func(FC_TLS_ANY_VERSION, 0, 0, FCTLS_client_method,
        tls_undefined_function, tls_statem_connect, tls1_2_num_ciphers,
        tls1_2_get_cipher, tls1_2_get_cipher_by_char,
        &TLS_enc_data, &tls_client_read_statem_proc,
        &tls_client_write_statem_proc)

IMPLEMENT_tls_meth_func(FC_TLS1_2_VERSION, 0, 0, FCTLSv1_2_client_method,
        tls_undefined_function, tls12_statem_connect, tls1_2_num_ciphers,
        tls1_2_get_cipher, tls1_2_get_cipher_by_char,
        &TLS_enc_data, &tls12_client_read_statem_proc,
        &tls12_client_write_statem_proc)

IMPLEMENT_tls_meth_func(FC_TLS1_2_VERSION, 0, 0, FCTLSv1_2_server_method,
        tls12_statem_accept, tls_undefined_function, tls1_2_num_ciphers,
        tls1_2_get_cipher, tls1_2_get_cipher_by_char,
        &TLS_enc_data, &tls12_server_read_statem_proc,
        &tls12_server_write_statem_proc)

IMPLEMENT_tls_meth_func(FC_TLS1_3_VERSION, 0, 0, FCTLSv1_3_client_method,
        tls_undefined_function, tls13_statem_connect, tls1_3_num_ciphers,
        tls1_3_get_cipher, tls1_3_get_cipher_by_char,
        &TLSv1_3_enc_data, &tls13_client_read_statem_proc,
        &tls13_client_write_statem_proc)

IMPLEMENT_tls_meth_func(FC_TLS1_3_VERSION, 0, 0, FCTLSv1_3_server_method,
        tls13_statem_accept, tls_undefined_function, tls1_3_num_ciphers,
        tls1_3_get_cipher, tls1_3_get_cipher_by_char,
        &TLSv1_3_enc_data, &tls13_server_read_statem_proc,
        &tls13_server_write_statem_proc)

