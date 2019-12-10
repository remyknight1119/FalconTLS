#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <falcontls/types.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <falcontls/buffer.h>

#include "internal/bio.h"
#include "internal/buffer.h"

/*
 * BIO memory stores buffer and read pointer
 * however the roles are different for read only BIOs.
 * In that case the readp just stores the original state
 * to be used for reset.
 */
typedef struct bio_buf_mem_st {
    FC_BUF_MEM  *bm_buf;   /* allocated buffer */
    FC_BUF_MEM  *bm_readp; /* read pointer */
} BIO_BUF_MEM;

static int mem_write(FC_BIO *bi, const char *buf, int num);
static int mem_read(FC_BIO *bi, char *buf, int size);
static int mem_puts(FC_BIO *bi, const char *str);
static long mem_ctrl(FC_BIO *bi, int cmd, long arg1, void *arg2);
static int mem_new(FC_BIO *bi);
static int mem_free(FC_BIO *data);

static const FC_BIO_METHOD mem_method = {
    .bm_type = FC_BIO_TYPE_MEM,
    .bm_name = "memory buffer",
    .bm_write = mem_write,
    .bm_read = mem_read,
    .bm_puts = mem_puts,
    .bm_ctrl = mem_ctrl,
    .bm_create = mem_new,
    .bm_destroy = mem_free,
};

const FC_BIO_METHOD *
FC_BIO_s_mem(void)
{
    return &mem_method;   
}

static int
mem_write(FC_BIO *bi, const char *buf, int num)
{
    return 1;
}

static int
mem_read(FC_BIO *bi, char *buf, int size)
{
    return 1;
}

static int
mem_puts(FC_BIO *bi, const char *str)
{
    return 1;
}

static long
mem_ctrl(FC_BIO *bi, int cmd, long num, void *ptr)
{
    BIO_BUF_MEM *bbm = (BIO_BUF_MEM *)bi->b_ptr;
    FC_BUF_MEM  *bm = NULL;
    char        **pptr = NULL;
    long        ret = 1;

    bm = bbm->bm_readp;

    switch (cmd) {
        case FC_BIO_CTRL_INFO:
            ret = (long)bm->bm_length;
            if (ptr != NULL) {
                pptr = (char **)ptr;
                *pptr = (char *)&(bm->bm_data[0]);
            }
            break;
        case FC_BIO_CTRL_SET_CLOSE:
            bi->b_shutdown = (int)num;
            break;
        default:
            ret = 0;
            break;
    }

    return ret;
}

static int
mem_init(FC_BIO *bi, unsigned long flags)
{
    BIO_BUF_MEM *bb = FALCONTLS_calloc(sizeof(*bb));

    if (bb == NULL) {
        return 0;
    }

    if ((bb->bm_buf = FC_BUF_MEM_new_ex(flags)) == NULL) {
        FALCONTLS_free(bb);
        return 0;
    }

    if ((bb->bm_readp = FALCONTLS_calloc(sizeof(*bb->bm_readp))) == NULL) {
        FC_BUF_MEM_free(bb->bm_buf);
        FALCONTLS_free(bb);
        return 0;
    }

    *bb->bm_readp = *bb->bm_buf;
    bi->b_shutdown = 1;
    bi->b_init = 1;
    bi->b_num = -1;
    bi->b_ptr = (char *)bb;
    return 1;
}

static int
mem_new(FC_BIO *bi)
{
    return mem_init(bi, 0L);
}

static int mem_buf_free(FC_BIO *bi)
{
    if (bi == NULL) {
        return 0;
    }

    if (bi->b_shutdown && bi->b_init && bi->b_ptr != NULL) {
        BIO_BUF_MEM *bb = (BIO_BUF_MEM *)bi->b_ptr;
        FC_BUF_MEM *b = bb->bm_buf;
        FC_BUF_MEM_free(b);
    }
    return 1;
}

static int
mem_free(FC_BIO *bi)
{
    BIO_BUF_MEM     *bb = NULL;

    if (bi == NULL) {
        return 0;
    }

    bb = (BIO_BUF_MEM *)bi->b_ptr;
    if (!mem_buf_free(bi)) {
        return 0;
    }

    FALCONTLS_free(bb->bm_readp);
    FALCONTLS_free(bb);
    return 1;
}



