#include <falcontls/types.h>
#include <internal/buffer.h>
#include <fc_lib.h>

#include "packet_locl.h"
#include "tls_locl.h"
#include "tls1.h"
#include "record_locl.h"

static const unsigned char ecformats_default[] = {
    TLSEXT_ECPOINTFORMAT_uncompressed,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime,
    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2
};

void
tls_set_record_header(TLS *s, void *record, uint16_t tot_len, int mt)
{
    record_t    *r = NULL;

    r = record;
    r->rd_version.pv_version = FC_HTONS(0x301);
    r->rd_type = mt;
    r->rd_len = FC_HTONS(tot_len);
}

void
tls1_get_formatlist(TLS *s, const unsigned char **pformats,
                         size_t *num_formats)
{
    /*
     * If we have a custom point format list use it otherwise use default
     */
    if (s->tls_ext.ecpointformats) {
        *pformats = s->tls_ext.ecpointformats;
        *num_formats = s->tls_ext.ecpointformats_len;
    } else {
        *pformats = ecformats_default;
        *num_formats = sizeof(ecformats_default);
    }
}


