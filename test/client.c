#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>

#include <falcontls/types.h>
#include <fc_log.h>
#include <fc_lib.h>

#include "tls_test.h"

#define FC_DEF_IP_ADDRESS       "127.0.0.1"
#define FC_DEF_PORT             "448"
#define FC_BUF_MAX_LEN          1000

#define FC_TLS_TYPE_FALCONTLS       1
#define FC_TLS_TYPE_OPENSSL         2

static const char *
fc_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
fc_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"dest", 0, 0, 'd'},
	{"port", 0, 0, 'p'},
	{"certificate", 0, 0, 'c'},
	{"key", 0, 0, 'k'},
	{0, 0, 0, 0}
};

static const char *
fc_options[] = {
	"--dest         -d	dest IP address\n",	
	"--port         -p	Port for TLS communication\n",	
	"--certificate  -c	certificate file\n",	
	"--key          -k	private key file\n",	
	"--help         -H	Print help information\n",	
};

static int 
fc_ssl_client_main(struct sockaddr_in *dest, char *cf, char *key,
        const PROTO_SUITE *suite, char *peer_cf)
{
    int         sockfd = 0;
    //int         len = 0;
    //char        buffer[FC_BUF_MAX_LEN] = {};
    TLS_CTX     *ctx = NULL;
    TLS         *ssl = NULL;
    int         ret = FC_OK;

    suite->ps_library_init();
    suite->ps_add_all_algorithms();
    suite->ps_load_error_strings();
    ctx = suite->ps_ctx_client_new(0);
    if (ctx == NULL) {
        return FC_ERROR;
    }

    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (cf && suite->ps_ctx_use_certificate_file(ctx, cf) < 0) {
        FC_LOG("Load certificate %s failed!\n", cf);
        exit(1);
    }

    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, key) < 0) {
        FC_LOG("Load private key %s failed!\n", key);
        exit(1);
    }

#if 0
    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        FC_LOG("Check private key failed!\n");
        //exit(1);
    }
#endif

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    FC_LOG("socket created\n");
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    FC_LOG("server connected\n");
    if (peer_cf) {
        suite->ps_set_verify(ctx, suite->ps_verify_mode, peer_cf);
    }
    /* 基于 ctx 产生一个新的 TLS */
    ssl = suite->ps_ssl_new(ctx);
    suite->ps_set_fd(ssl, sockfd);
    /* 建立 TLS 连接 */
    if (suite->ps_connect(ssl) == FC_ERROR) {
        FC_LOG("Client connect failed!\n");
        exit(1);
    } 
    //printf("Connected with %s encryption\n", TLS_get_cipher(ssl));
    //ShowCerts(ssl);

#if 0
    if (suite->ps_get_verify_result(ssl) != FC_OK) {
        FC_LOG("Server cert verify failed!\n");
        exit(1);
    }
    /* 发消息给服务器 */
    len = suite->ps_write(ssl, FC_TEST_REQ, sizeof(FC_TEST_REQ));
    if (len < 0) {
        FC_LOG("Client消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
             buffer, errno, strerror(errno));
        exit(1);
    }
    FC_LOG("Client消息'%s'发送成功,共发送了%d 个字节!\n",
            FC_TEST_REQ, len);

    /* 接收服务器来的消息 */
    len = suite->ps_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, FC_TEST_RESP) == 0) {
        FC_LOG("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        FC_LOG("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
             errno, strerror(errno), len);
        ret = FC_ERROR;
    }
#endif

    /* 关闭连接 */
    suite->ps_shutdown(ssl);
    suite->ps_ssl_free(ssl);
    close(sockfd);
    suite->ps_ctx_free(ctx);
    return ret;
}

static int
fc_ssl_client(struct sockaddr_in *addr, char *cf, 
        char *key, const PROTO_SUITE *suite, char *peer_cf)
{
    return fc_ssl_client_main(addr, cf, key, suite, peer_cf);
}

static void 
fc_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", fc_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < FC_ARRAY_SIZE(fc_options); index++) {
		fprintf(stdout, "  %s", fc_options[index]);
	}
}

static const char *
fc_optstring = "Hp:c:k:d:";

int
main(int argc, char **argv)  
{
    int                     c = 0;
    struct sockaddr_in      addr = {
        .sin_family = AF_INET,
    };
    uint16_t                pport = 0;
    const PROTO_SUITE       *client_suite = &fc_tls_suite;
    char                    *ip = FC_DEF_IP_ADDRESS;
    char                    *port = FC_DEF_PORT;
    char                    *cf = NULL;
    char                    *key = NULL;
    char                    *client_cf = NULL;
    char                    *client_key = NULL;

    while ((c = getopt_long(argc, argv, fc_optstring, 
                    fc_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                fc_help();
                return FC_OK;

            case 'p':
                port = optarg;
                break;

            case 'd':
                ip = optarg;
                break;

            case 'c':
                cf = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            default:
                fc_help();
                return -FC_ERROR;
        }
    }

    pport = atoi(port);
    addr.sin_port = htons(pport);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (cf != NULL) {
        if (key == NULL) {
            FC_LOG("Please input key by -k!\n");
            return -FC_ERROR;
        }

        client_cf = strstr(cf, ",");
        if (client_cf == NULL) {
            FC_LOG("Client certificate not set!\n");
            return -FC_ERROR;
        }
        *client_cf++ = 0;
        client_key = strstr(key, ",");
        if (client_key == NULL) {
            FC_LOG("Client key not set!\n");
            return -FC_ERROR;
        }
        *client_key++ = 0;
    }

    return -fc_ssl_client(&addr, client_cf, client_key, 
            client_suite, cf);
}
