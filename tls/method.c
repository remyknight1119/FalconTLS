
#include <falcontls/tls.h>
#include "statem.h"
#include "tls_locl.h"

IMPLEMENT_tls_meth_func(FC_TLS_ANY_VERSION, 0, 0,
         FCTLS_method,                    
         tls_statem_accept,            
         tls_statem_connect, &TLSv1_2_enc_data)

IMPLEMENT_tls_meth_func(FC_TLS_ANY_VERSION, 0, 0,
         FCTLS_client_method,                    
         tls_undefined_function,            
         tls_statem_connect, &TLSv1_2_enc_data)


IMPLEMENT_tls_meth_func(FC_TLS1_2_VERSION, 0, 0,
         FCTLSv1_2_method,                    
         tls12_statem_accept,            
         tls12_statem_connect, &TLSv1_2_enc_data)

IMPLEMENT_tls_meth_func(FC_TLS1_3_VERSION, 0, 0,
         FCTLSv1_3_method,                    
         tls13_statem_accept,            
         tls13_statem_connect, &TLSv1_3_enc_data)

IMPLEMENT_tls_meth_func(FC_TLS1_2_VERSION, 0, 0,
         FCTLSv1_2_client_method,                    
         tls_undefined_function,            
         tls12_statem_connect, &TLSv1_2_enc_data)

IMPLEMENT_tls_meth_func(FC_TLS1_2_VERSION, 0, 0,
         FCTLSv1_2_server_method,                    
         tls12_statem_accept,            
         tls_undefined_function, &TLSv1_2_enc_data)

IMPLEMENT_tls_meth_func(FC_TLS1_3_VERSION, 0, 0,
         FCTLSv1_3_client_method,                    
         tls_undefined_function,            
         tls13_statem_connect, &TLSv1_3_enc_data)

IMPLEMENT_tls_meth_func(FC_TLS1_3_VERSION, 0, 0,
         FCTLSv1_3_server_method,                    
         tls13_statem_accept,            
         tls_undefined_function, &TLSv1_3_enc_data)

