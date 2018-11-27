#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"

int
tls_write_bytes(TLS *s, int type, const void *buf, size_t len,
        size_t *written)
{
    size_t tot = 0;

    tot = s->tls_rlayer.rl_wnum;

    s->tls_rlayer.rl_wnum = 0;

    FC_LOG("tot = %d\n", (int)tot);
    return 0;
}
