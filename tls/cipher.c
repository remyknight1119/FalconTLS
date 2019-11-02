#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls_locl.h"
#include "tls1_3.h"
#include "cipher.h"

#define CIPHER_ADD      1
#define CIPHER_KILL     2
#define CIPHER_DEL      3
#define CIPHER_ORD      4
#define CIPHER_SPECIAL  5
/*
* Bump the ciphers to the top of the list.
* This rule isn't currently supported by the public cipherstring API.
*/                      
#define CIPHER_BUMP     6

typedef struct cipher_order_t {
    const TLS_CIPHER        *co_cipher;
    int                     co_active;
    int                     co_dead;
    struct cipher_order_t   *co_next;
    struct cipher_order_t   *co_prev;
} CIPHER_ORDER;

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

static void
tls_cipher_collect_ciphers(const TLS_METHOD *method, int num_of_ciphers,
                            CIPHER_ORDER *co_list, CIPHER_ORDER **head_p,
                            CIPHER_ORDER **tail_p)
{
    const TLS_CIPHER        *c = NULL;
    int                     i = 0;
    int                     co_list_num = 0;

    co_list_num = 0;
    for (i = 0; i < num_of_ciphers; i++) {
        c = method->md_get_cipher(i);
        if (c == NULL) {
            continue;
        }
        co_list[co_list_num].co_cipher = c;
        co_list[co_list_num].co_next = NULL;
        co_list[co_list_num].co_prev = NULL;
        co_list[co_list_num].co_active = 0;
        co_list_num++;
    }

    if (co_list_num == 0) {
        return;
    }

    co_list[0].co_prev = NULL;
    if (co_list_num > 1) {
        co_list[0].co_next = &co_list[1];
        for (i = 1; i < co_list_num - 1; i++) {
            co_list[i].co_prev = &co_list[i - 1];
            co_list[i].co_next = &co_list[i + 1];
        }
        co_list[co_list_num - 1].co_prev = &co_list[co_list_num - 2];
    }

    co_list[co_list_num - 1].co_next = NULL;
    *head_p = &co_list[0];
    *tail_p = &co_list[co_list_num - 1];
}

FC_STACK_OF(TLS_CIPHER) *
tls_create_cipher_list(const TLS_METHOD *method, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list_by_id, CERT *c)
{
    FC_STACK_OF(TLS_CIPHER)     *cipherstack = NULL;
    const TLS_CIPHER            *ciph = NULL;
    CIPHER_ORDER                *co_list = NULL;
    CIPHER_ORDER                *head = NULL;
    CIPHER_ORDER                *tail = NULL;
    CIPHER_ORDER                *curr = NULL;
    int                         i = 0;
    int                         num_of_ciphers = 0;

    if (cipher_list == NULL || cipher_list_by_id == NULL) {
        return NULL;
    }

    num_of_ciphers = method->md_num_ciphers();

    co_list = FALCONTLS_malloc(sizeof(*co_list) * num_of_ciphers);
    if (co_list == NULL) {
        FC_LOG("Malloc co_list failed!\n");
        return (NULL);
    }

    tls_cipher_collect_ciphers(method, num_of_ciphers, co_list, &head, &tail);

    if ((cipherstack = sk_TLS_CIPHER_new_null()) == NULL) {
        FC_LOG("New TLS_CIPHER failed!\n");
        return (NULL);
    }


    for (i = 0; i < tls1_3_num_ciphers(); i++) {
        ciph = tls1_3_get_cipher(i);
        if (ciph == NULL) {
            continue;
        }
        if (!sk_TLS_CIPHER_push(cipherstack, ciph)) {
            sk_TLS_CIPHER_free(cipherstack);
            FC_LOG("push CIPHER %s failed!\n", ciph->cp_name);
            return NULL;
        }
    }
 
    for (curr = head; curr != NULL; curr = curr->co_next) {
        if (!sk_TLS_CIPHER_push(cipherstack, curr->co_cipher)) {
            sk_TLS_CIPHER_free(cipherstack);
            FC_LOG("push CIPHER %s failed!\n", curr->co_cipher->cp_name);
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


