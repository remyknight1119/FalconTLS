
#include <falcontls/crypto.h>
#include <openssl/crypto.h>

int
FALCONTLS_init_crypto(void)
{
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG
                | OPENSSL_INIT_ADD_ALL_CIPHERS
                | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)) {
        return 0;
    }

    return 1;
}
