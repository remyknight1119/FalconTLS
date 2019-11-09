lib_LTLIBRARIES = libfc_crypto.la
libfc_crypto_la_SOURCES = mem.c bio/bio_lib.c bio/bio_file.c \
						  bio/bio_socket.c buffer/buffer.c \
						  stack/stack.c x509/x509.c x509/x509_cmp.c \
						  x509/x509_set.c x509/x_x509.c init.c \
						  evp/pmeth_gn.c  evp/pmeth_lib.c evp/p_lib.c \
						  ec/ec_key.c ec/ec_lib.c pem/pem.c pem/pem_lib.c \
						  evp/pmeth_fn.c
libfc_crypto_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
