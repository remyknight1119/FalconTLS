
#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"

static int
tls_state_machine(TLS *s, int server)
{
    return 1;
}

int
tls_statem_accept(TLS *s)
{
    return tls_state_machine(s, 1);
}

int
tls_statem_connect(TLS *s)
{
    return tls_state_machine(s, 0);
}

int
TLS_in_init(TLS *s)
{
    //return s->tls_statem.sm_in_init;
    return 1;
}


