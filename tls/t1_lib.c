#include <falcontls/types.h>
#include <internal/buffer.h>
#include <fc_lib.h>

#include "packet_locl.h"
#include "tls_locl.h"
#include "record_locl.h"
 
void
tls_set_record_header(TLS *s, void *record, uint16_t tot_len, int mt)
{
    record_t    *r = NULL;

    r = record;
    r->rd_version.pv_version = FC_HTONS(s->tls_version);
    r->rd_type = mt;
    r->rd_len = FC_HTONS(tot_len);
}
