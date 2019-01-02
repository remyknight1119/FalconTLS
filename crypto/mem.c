#include <stdlib.h>
#include <string.h>

#include "fc_log.h"

void *
FC_CRYPTO_malloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = malloc(num);
    if (ptr == NULL) {
        FC_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void *
FC_CRYPTO_calloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = calloc(1, num);
    if (ptr == NULL) {
        FC_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void *
FC_CRYPTO_realloc(void *str, size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = realloc(str, num);
    if (ptr == NULL) {
        FC_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void *
FC_CRYPTO_memdup(void *data, size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    if (data == NULL) {
        return NULL;
    }

    ptr = FC_CRYPTO_malloc(num, file, line);
    if (ptr == NULL) {
        return NULL;
    }

    return memcpy(ptr, data, num);
}

void
FC_CRYPTO_free(void *ptr, const char *file, int line)
{
    //FC_LOG("free %p!(%s %d)\n", ptr, file, line);
    free(ptr);
}
