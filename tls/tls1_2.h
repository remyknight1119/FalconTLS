#ifndef __FC_TLS1_2_H__
#define __FC_TLS1_2_H__

int  tls1_2_new(TLS *s);
void tls1_2_clear(TLS *s);
void tls1_2_free(TLS *s);
int tls1_2_accept(TLS *s);
int tls1_2_connect(TLS *s);
int tls1_2_read(TLS *s, void *buf, int len);
int tls1_2_peek(TLS *s, void *buf, int len);
int tls1_2_num_ciphers(void);
const TLS_CIPHER *tls1_2_get_cipher(uint32_t u);
const TLS_CIPHER *tls1_2_get_cipher_by_char(const uint8_t *p);
int tls1_2_put_cipher_by_char(const TLS_CIPHER *c, uint8_t *p);


#endif
