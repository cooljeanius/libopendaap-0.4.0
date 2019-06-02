SUBDIRS = authentication debug mdnsd
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/debug
AM_CFLAGS = -Wall -Wextra -D_GNU_SOURCE

lib_LTLIBRARIES = libopendaap.la
libopendaap_la_SOURCES = client.c \
                         daap.c daap.h \
                         daap_contentcodes.h daap_readtypes.h \
                         discover.c discover.h \
                         dmap_generics.c dmap_generics.h \
                         global.c \
                         http_client.c http_client.h \
                         portability.h private.h \
                         threadpool.c threadpool.h \
                         thread.h \
                         ioloop.c ioloop.h \
                         endian_swap.h
libopendaap_la_LDFLAGS = -version-number 0:1:0 -lpthread
libopendaap_la_LIBADD = authentication/libauthentication.la \
                        debug/libdebug.la \
                        mdnsd/libmdnsd.la
man_MANS = libopendaap.3

apiheadersdir = $(includedir)/daap
nobase_apiheaders_HEADERS = client.h portability.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opendaap.pc

EXTRA_DIST = \
             $(man_MANS)

