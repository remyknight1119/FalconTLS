#ifndef __FC_INTERNAL_BUFFER_H__
#define __FC_INTERNAL_BUFFER_H__

#include <falcontls/types.h>

struct fc_buf_mem_t {
    char        *bm_data;
    size_t      bm_length;              /* current number of bytes */
    size_t      bm_max;                 /* size of buffer */
    ulong       bm_flags;
};

#define GET_BUF_DATA(buf)   buf->bm_data

#endif
