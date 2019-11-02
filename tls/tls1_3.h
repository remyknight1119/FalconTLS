#ifndef __FC_TLS1_3_H__
#define __FC_TLS1_3_H__

int  tls1_3_new(TLS *s);
void tls1_3_clear(TLS *s);
void tls1_3_free(TLS *s);
int tls1_3_accept(TLS *s);
int tls1_3_connect(TLS *s);
int tls1_3_read(TLS *s, void *buf, int len);
int tls1_3_peek(TLS *s, void *buf, int len);
int tls1_3_num_ciphers(void);
const TLS_CIPHER *tls1_3_get_cipher(uint32_t u);
const TLS_CIPHER *tls1_3_get_cipher_by_char(const uint8_t *p);
int tls1_3_put_cipher_by_char(const TLS_CIPHER *c, WPACKET *pkt, size_t *len);


#endif
