#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([libopendaap], 0.4.0, [crazney@craz.net])

AM_INIT_AUTOMAKE([dist-bzip2])
AM_MAINTAINER_MODE
AM_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL

AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_PID_T

AC_CHECK_FUNCS([memset strdup])

AC_CHECK_TYPES([int64_t, int32_t,
                int16_t, int8_t],,
                AC_ERROR("signed fixed size integers not found"))

AC_CHECK_TYPES([u_int64_t, u_int32_t,
                u_int16_t, u_int8_t],,
                [have_u_intxx_t=no])

if test "$have_u_intxx_t" = "no"; then
    AC_CHECK_TYPES([uint64_t, uint32_t,
                    uint16_t, uint8_t],,
                    AC_ERROR("unsigned fixed size integers not found"))
fi

AC_CACHE_CHECK([whether the compiler supports __alignof__], ac_cv_c_alignof,
    AC_TRY_COMPILE(,[int alignint = __alignof__(int)],
                   [ac_cv_c_alignof="yes"],
                   [ac_cv_c_alignof="no"]))

if test "$ac_cv_c_alignof" = "yes"; then
    AC_DEFINE(HAVE___ALIGNOF__, 1, [Define if the compiler supports __alignof__])
fi


AC_OUTPUT([Makefile
           debug/Makefile
           authentication/Makefile
           mdnsd/Makefile
           opendaap.pc])
