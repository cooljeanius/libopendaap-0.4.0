noinst_LTLIBRARIES = libdebug.la
libdebug_la_SOURCES = debug.c debug.h
AM_CPPFLAGS = -I.. -I$(srcdir) -I$(srcdir)/..

DISTCLEANFILES = .DS_Store

distclean-local:
	-rm -rfv .deps || rmdir .deps
.PHONY: distclean-local
