#ifndef __FC_CRYPTO_H__
#define __FC_CRYPTO_H__

#include <sys/types.h>
#include <stdint.h>

#include <falcontls/types.h>

#define FC_CRYPTO_add(a,b,c)       ((*(a))+=(b))
#define FC_PEM_DATA_LEN             80

extern void *FC_CRYPTO_malloc(size_t num, const char *file, int line);
extern void *FC_CRYPTO_calloc(size_t num, const char *file, int line);
extern void *FC_CRYPTO_realloc(void *str, size_t num, 
            const char *file, int line);
extern void FC_CRYPTO_free(void *ptr);

#define FALCONTLS_malloc(size)          \
            FC_CRYPTO_malloc(size, __FUNCTION__, __LINE__)
#define FALCONTLS_calloc(size)          \
            FC_CRYPTO_calloc(size, __FUNCTION__, __LINE__)
#define FALCONTLS_realloc(ptr, size)    \
            FC_CRYPTO_realloc(ptr, size, __FUNCTION__, __LINE__)
#define FALCONTLS_free(ptr)             FC_CRYPTO_free(ptr)

#endif
