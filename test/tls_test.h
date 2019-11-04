#ifndef __TLS_TEST_H__
#define __TLS_TEST_H__

#define FC_OK       0
#define FC_ERROR    -1

typedef struct fc_proto_suite_t {
    long    ps_verify_mode;
    int     (*ps_library_init)(void);
    void    (*ps_add_all_algorithms)(void);
    void    (*ps_load_error_strings)(void);
    void    *(*ps_ctx_client_new)(int version);
    void    *(*ps_ctx_server_new)(int version);
    int     (*ps_ctx_use_certificate_file)(void *ctx, const char *file);
    int     (*ps_ctx_use_privateKey_file)(void *ctx, const char *file);
    int     (*ps_ctx_check_private_key)(const void *ctx);
    int     (*ps_ctx_set_ciphers)(void *ctx);
    long    (*ps_ctx_set_max_proto_version)(void *ctx, long version);
    long    (*ps_ctx_set_min_proto_version)(void *ctx, long version);
    void    (*ps_ctx_set_security_callback)(void *ctx);
    void    *(*ps_ssl_new)(void *ctx);
    int     (*ps_set_fd)(void *s, int fd);
    int     (*ps_accept)(void *s);
    int     (*ps_connect)(void *s);
    int     (*ps_read)(void *s, void *buf, int num);
    int     (*ps_write)(void *s, const void *buf, int num);
    int     (*ps_shutdown)(void *s);
    void    (*ps_ssl_free)(void *s);
    void    (*ps_ctx_free)(void *ctx);
    void    (*ps_set_verify)(void *s, int mode, char *peer_cf);
    int     (*ps_get_verify_result)(void *s);
    long    (*ps_parse_version)(const char *);
} PROTO_SUITE;

typedef struct _fc_version_t {
    const char  *name;
    long        version;
} fc_version_t;

extern const PROTO_SUITE fc_openssl_suite;
extern const PROTO_SUITE fc_tls_suite;

#endif
