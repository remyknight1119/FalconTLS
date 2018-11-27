#ifndef __FC_RECORD_H__
#define __FC_RECORD_H__



int tls_write_bytes(TLS *s, int type, const void *buf, size_t len,
        size_t *written);

#endif
