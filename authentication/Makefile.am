noinst_LTLIBRARIES = libauthentication.la
libauthentication_la_SOURCES = hasher.c md5.c hasher.h md5.h
AM_CFLAGS = -Wall -Wextra
AM_CPPFLAGS = ${acl_cv_wp}-I.. ${acl_cv_wp}-I$(srcdir) \
  ${acl_cv_wp}-I$(srcdir)/..

DISTCLEANFILES = .DS_Store

distclean-local:
	-rm -rfv .deps || rmdir .deps
.PHONY: distclean-local
