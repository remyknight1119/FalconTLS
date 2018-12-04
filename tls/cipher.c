#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "cipher.h"


FC_STACK_OF(TLS_CIPHER) *
tls_create_cipher_list(const TLS_METHOD *method, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list_by_id, CERT *c)
{
    FC_STACK_OF(TLS_CIPHER)     *cipherstack = NULL;
    const TLS_CIPHER            *ciph = NULL;
    int                         i = 0;
    int                         num_of_ciphers = 0;

    if (cipher_list == NULL || cipher_list_by_id == NULL) {
        return NULL;
    }

    num_of_ciphers = method->md_num_ciphers();

    if ((cipherstack = sk_TLS_CIPHER_new_null()) == NULL) {
        FC_LOG("New TLS_CIPHER failed!\n");
        return (NULL);
    }

    for (i = 0; i < num_of_ciphers; i++) {
        ciph = method->md_get_cipher(i);
        if (ciph == NULL) {
            continue;
        }
        if (!sk_TLS_CIPHER_push(cipherstack, ciph)) {
            sk_TLS_CIPHER_free(cipherstack);
            FC_LOG("push CIPHER %s failed!\n", ciph->cp_name);
            return NULL;
        }
    }
 
    *cipher_list = cipherstack;
    return cipherstack;
}

const TLS_CIPHER *
tls_get_cipher_by_char(TLS *s, const uint8_t *ptr)
{
    return s->tls_method->md_get_cipher_by_char(ptr);
}


