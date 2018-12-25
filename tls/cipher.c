#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "cipher.h"

int
tls_cipher_ptr_id_cmp(const TLS_CIPHER *const *ap,
                          const TLS_CIPHER *const *bp)
{
    if ((*ap)->cp_id > (*bp)->cp_id) {
        return 1;
    }

    if ((*ap)->cp_id < (*bp)->cp_id) {
        return -1;
    }

    return 0;
}

static int
update_cipher_list_by_id(FC_STACK_OF(TLS_CIPHER) **cipher_list_by_id,
                                    FC_STACK_OF(TLS_CIPHER) *cipherstack)
{
    FC_STACK_OF(TLS_CIPHER) *tmp_cipher_list = sk_TLS_CIPHER_dup(cipherstack);

    if (tmp_cipher_list == NULL) {
        return 0;
    }

    sk_TLS_CIPHER_free(*cipher_list_by_id);
    *cipher_list_by_id = tmp_cipher_list;

    (void)sk_TLS_CIPHER_set_cmp_func(*cipher_list_by_id, tls_cipher_ptr_id_cmp);
    sk_TLS_CIPHER_sort(*cipher_list_by_id);

    return 1;
}

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

    for (i = num_of_ciphers - 1; i >= 0; i--) {
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
 
    if (!update_cipher_list_by_id(cipher_list_by_id, cipherstack)) {
        FC_LOG("Update cipher list by id failed!\n");
        return NULL;
    }

    *cipher_list = cipherstack;
    return cipherstack;
}

const TLS_CIPHER *
tls_get_cipher_by_char(TLS *s, const uint8_t *ptr)
{
    return s->tls_method->md_get_cipher_by_char(ptr);
}


