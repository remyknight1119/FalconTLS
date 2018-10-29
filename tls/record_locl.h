#ifndef __FC_RECORD_LOCL_H__
#define __FC_RECORD_LOCL_H__

#include <sys/types.h>

struct _version_t {
    union {
        uint16_t    pv_version;
        struct {
            uint8_t pv_major;
            uint8_t pv_minor;
        };
    };
} __attribute__ ((__packed__));

typedef struct _version_t version_t;

struct _fc_record_t {
    uint8_t         rd_type;
    version_t       rd_version;
    uint16_t        rd_len;
} __attribute__ ((__packed__));

typedef struct _record_t record_t;

#endif
