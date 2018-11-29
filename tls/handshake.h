#ifndef __FC_TLS_HANDSHAKE_H__
#define __FC_TLS_HANDSHAKE_H__

#define tls_set_handshake_header(s, pkt, mt) \
        s->tls_method->md_tls_enc->em_set_handshake_header(s, pkt, mt)


#endif
