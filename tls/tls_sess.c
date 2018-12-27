
#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/types.h>

#include "tls_locl.h"

TLS_SESSION *
TLS_SESSION_new(void)
{
    TLS_SESSION     *ss = NULL;

    ss = FALCONTLS_calloc(sizeof(*ss));

    return ss;
}

void
TLS_SESSION_free(TLS_SESSION *ss)
{
    if (ss == NULL) {
        return;
    }

    FALCONTLS_free(ss);
}

int
tls_get_new_session(TLS *s, int session)
{
    TLS_SESSION     *ss = NULL;

    if ((ss = TLS_SESSION_new()) == NULL) {
        return 0;
    }

    TLS_SESSION_free(s->tls_session);
    s->tls_session = NULL;

    s->tls_session = ss;

    return 1;
}
