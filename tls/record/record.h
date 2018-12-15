#ifndef __FC_RECORD_H__
#define __FC_RECORD_H__

int tls_write_bytes(TLS *s, int type, const void *buf, size_t len,
        size_t *written);
int tls_read_bytes(TLS *s, int type, int *recvd_type, const void *buf,
        size_t len, size_t *read_bytes);

#endif
