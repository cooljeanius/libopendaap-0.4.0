noinst_LTLIBRARIES = libmdnsd.la
libmdnsd_la_SOURCES = 1035.c 1035.h \
                     mdnsd.c mdnsd.h
AM_CFLAGS = -Wall -Wextra
AM_CPPFLAGS = -I.. -I$(srcdir) -I$(srcdir)/..

DISTCLEANFILES = .DS_Store

distclean-local:
	-rm -rfv .deps || rmdir .deps
.PHONY: distclean-local
