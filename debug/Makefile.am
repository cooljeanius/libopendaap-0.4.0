noinst_LTLIBRARIES = libdebug.la
libdebug_la_SOURCES = debug.c debug.h
AM_CPPFLAGS = ${acl_cv_wp}-I.. ${acl_cv_wp}-I$(srcdir) \
  ${acl_cv_wp}-I$(srcdir)/..

DISTCLEANFILES = .DS_Store

distclean-local:
	-rm -rfv .deps || rmdir .deps
.PHONY: distclean-local
