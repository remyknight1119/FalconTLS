lib_LTLIBRARIES = libfc_tls.la
libfc_tls_la_SOURCES = tls_lib.c tls_cert.c method.c statem/statem.c \
					   statem/statem_clnt.c statem/statem_srvr.c \
					   record/record_buffer.c tls1_2.c record/rec_layer.c \
					   statem/statem_lib.c packet.c t1_lib.c
libfc_tls_la_LDFLAGS = -version-info 1
libfc_tls_la_LIBADD = $(srcdir)/../crypto/libfc_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include -Istatem -Irecord
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
