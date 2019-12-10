#ifndef __FC_BIO_H__
#define __FC_BIO_H__

#include <falcontls/types.h>

#define FC_OPENSSL 1

enum {
    FC_BIO_C_RESET = 1,
    FC_BIO_C_EOF,
    FC_BIO_C_INFO,
    FC_BIO_C_FILE_SEEK,
    FC_BIO_C_FILE_TELL,
    FC_BIO_C_SET_FILE_PTR,
    FC_BIO_C_SET_FILENAME,
    FC_BIO_C_GET_FILE_PTR,
    FC_BIO_C_GET_CLOSE,
    FC_BIO_C_SET_CLOSE,
    FC_BIO_C_FLUSH,
    FC_BIO_C_SET_FD,
    FC_BIO_C_GET_FD,
    FC_BIO_C_DUP,
};
 
/*
 * These are used in the following macros and are passed to FC_BIO_ctrl()
 */
#define FC_BIO_CTRL_RESET          1/* opt - rewind/zero etc */
#define FC_BIO_CTRL_EOF            2/* opt - are we at the eof */
#define FC_BIO_CTRL_INFO           3/* opt - extra tit-bits */
#define FC_BIO_CTRL_SET            4/* man - set the 'IO' type */
#define FC_BIO_CTRL_GET            5/* man - get the 'IO' type */
#define FC_BIO_CTRL_PUSH           6/* opt - internal, used to signify change */
#define FC_BIO_CTRL_POP            7/* opt - internal, used to signify change */
#define FC_BIO_CTRL_GET_CLOSE      8/* man - set the 'close' on free */
#define FC_BIO_CTRL_SET_CLOSE      9/* man - set the 'close' on free */
#define FC_BIO_CTRL_PENDING        10/* opt - is their more data buffered */
#define FC_BIO_CTRL_FLUSH          11/* opt - 'flush' buffered output */
#define FC_BIO_CTRL_DUP            12/* man - extra stuff for 'duped' BIO */
#define FC_BIO_CTRL_WPENDING       13/* opt - number of bytes still to write */
#define FC_BIO_CTRL_SET_CALLBACK   14/* opt - set callback function */
#define FC_BIO_CTRL_GET_CALLBACK   15/* opt - set callback function */

#define FC_BIO_CTRL_PEEK           29/* FC_BIO_f_buffer special */
#define FC_BIO_CTRL_SET_FILENAME   30/* FC_BIO_s_file special */

/* dgram BIO stuff */
#define FC_BIO_CTRL_DGRAM_CONNECT       31/* BIO dgram special */
#define FC_BIO_CTRL_DGRAM_SET_CONNECTED 32/* allow for an externally connected
                                         * socket to be passed in */
#define FC_BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33/* setsockopt, essentially */
#define FC_BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34/* getsockopt, essentially */
#define FC_BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35/* setsockopt, essentially */
#define FC_BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36/* getsockopt, essentially */

#define FC_BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37/* flag whether the last */
#define FC_BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38/* I/O operation tiemd out */

/* #ifdef IP_MTU_DISCOVER */
#define FC_BIO_CTRL_DGRAM_MTU_DISCOVER       39/* set DF bit on egress packets */
/* #endif */

#define FC_BIO_CTRL_DGRAM_QUERY_MTU          40/* as kernel for current MTU */
#define FC_BIO_CTRL_DGRAM_GET_FALLBACK_MTU   47
#define FC_BIO_CTRL_DGRAM_GET_MTU            41/* get cached value for MTU */
#define FC_BIO_CTRL_DGRAM_SET_MTU            42/* set cached value for MTU.
                                              * want to use this if asking
                                              * the kernel fails */

#define FC_BIO_CTRL_DGRAM_MTU_EXCEEDED       43/* check whether the MTU was
                                              * exceed in the previous write
                                              * operation */

#define FC_BIO_CTRL_DGRAM_GET_PEER           46
#define FC_BIO_CTRL_DGRAM_SET_PEER           44/* Destination for the data */

#define FC_BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   45/* Next DTLS handshake timeout
                                              * to adjust socket timeouts */
#define FC_BIO_CTRL_DGRAM_SET_DONT_FRAG      48

#define FC_BIO_CTRL_DGRAM_GET_MTU_OVERHEAD   49

#define FC_BIO_CTRL_DGRAM_SET_PEEK_MODE      71

#define FC_BIO_NOCLOSE          0x00
#define FC_BIO_CLOSE            0x01
#define FC_BIO_READ             0x02
#define FC_BIO_WRITE            0x04
#define FC_BIO_APPEND           0x08

/* There are the classes of BIOs */
#define FC_BIO_TYPE_DESCRIPTOR     0x0100 /* socket, fd, connect or accept */
#define FC_BIO_TYPE_FILTER         0x0200
#define FC_BIO_TYPE_SOURCE_SINK    0x0400

#define FC_BIO_TYPE_NONE             0
#define FC_BIO_TYPE_MEM            ( 1|FC_BIO_TYPE_SOURCE_SINK)
#define FC_BIO_TYPE_FILE           ( 2|FC_BIO_TYPE_SOURCE_SINK)
#define FC_BIO_TYPE_FD             ( 4|FC_BIO_TYPE_SOURCE_SINK|FC_BIO_TYPE_DESCRIPTOR)
#define FC_BIO_TYPE_SOCKET         ( 5|FC_BIO_TYPE_SOURCE_SINK|FC_BIO_TYPE_DESCRIPTOR)


#define FC_BIO_set_fp(b,fp,c)  FC_BIO_ctrl(b,FC_BIO_C_SET_FILE_PTR,c,(char *)fp)
#define FC_BIO_get_fp(b,fpp)   FC_BIO_ctrl(b,FC_BIO_C_GET_FILE_PTR,0,(char *)fpp)
#define FC_BIO_get_mem_data(b,pp)  FC_BIO_ctrl(b,FC_BIO_CTRL_INFO,0,(char *)(pp))

extern FC_BIO *FC_BIO_new(const FC_BIO_METHOD *method);
extern int FC_BIO_free(FC_BIO *a);
extern int FC_BIO_read_filename(FC_BIO *b, const char *name);
extern void FC_BIO_set_data(FC_BIO *a, void *ptr);
extern void *FC_BIO_get_data(FC_BIO *a);
extern void FC_BIO_set_init(FC_BIO *a, int init);
extern int FC_BIO_get_init(FC_BIO *a);
extern void FC_BIO_set_shutdown(FC_BIO *a, int shut);
extern int FC_BIO_get_shutdown(FC_BIO *a);
extern void FC_BIO_vfree(FC_BIO *a);
extern int FC_BIO_read(FC_BIO *b, void *out, int outl);
extern int FC_BIO_write(FC_BIO *b, const void *in, int inl);
extern int FC_BIO_puts(FC_BIO *b, const char *in);
extern int FC_BIO_gets(FC_BIO *b, char *in, int inl);
extern long FC_BIO_ctrl(FC_BIO *b, int cmd, long larg, void *parg);
extern const FC_BIO_METHOD *FC_BIO_s_file(void);
extern FC_BIO *FC_BIO_new_file(const char *filename, const char *mode);
extern const FC_BIO_METHOD *FC_BIO_s_socket(void);
extern int FC_BIO_set_fd(FC_BIO *b, int fd, int flags);
extern const FC_BIO_METHOD *FC_BIO_s_mem(void);

#endif
