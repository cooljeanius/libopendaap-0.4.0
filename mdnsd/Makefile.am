noinst_LTLIBRARIES = libmdnsd.la
libmdnsd_la_SOURCES = 1035.c 1035.h \
                     mdnsd.c mdnsd.h
AM_CFLAGS = -Wall -Wextra
AM_CPPFLAGS = ${acl_cv_wp}-I.. ${acl_cv_wp}-I$(srcdir) \
  ${acl_cv_wp}-I$(srcdir)/..

DISTCLEANFILES = .DS_Store

distclean-local:
	-rm -rfv .deps || rmdir .deps
.PHONY: distclean-local
