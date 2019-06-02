dnl#                                               -*- Autoconf -*-
dnl# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libopendaap],[0.4.0],[crazney@craz.net])dnl

AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([dist-bzip2 gnits])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([client.c])
AC_REQUIRE_AUX_FILE([install-sh])
AC_REQUIRE_AUX_FILE([mkinstalldirs])
AC_CONFIG_HEADERS([config.h])dnl

# Checks for programs.
AM_PROG_AR
AC_DEFUN([AC_REQUIRE_CC],[
  AC_REQUIRE([AC_PROG_CC])dnl
])dnl
AC_REQUIRE_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
LT_INIT

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread],[main])dnl

# Checks for header files.
AC_DEFUN([AC_REQUIRE_HEADER_STDC],[
  AC_REQUIRE([AC_HEADER_STDC])dnl
])dnl
AC_REQUIRE_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h sys/socket.h \
                  sys/time.h])dnl

# Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_CHECK_TYPES([int64_t, int32_t,
                int16_t, int8_t],,
                AC_MSG_ERROR("signed fixed size integers not found"))dnl

AC_CHECK_TYPES([u_int64_t, u_int32_t,
                u_int16_t, u_int8_t],,
                [have_u_intxx_t=no])dnl

if test "$have_u_intxx_t" = "no"; then
    AC_CHECK_TYPES([uint64_t, uint32_t,
                    uint16_t, uint8_t],,
                    AC_MSG_ERROR("unsigned fixed size integers not found"))
fi

AC_CACHE_CHECK([whether the compiler supports __alignof__], ac_cv_c_alignof,
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[int alignint = __alignof__(int)]])],[ac_cv_c_alignof="yes"],[ac_cv_c_alignof="no"]))dnl

if test "$ac_cv_c_alignof" = "yes"; then
    AC_DEFINE(HAVE___ALIGNOF__, 1, [Define if the compiler supports __alignof__])
fi

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero gettimeofday memset select socket strchr strdup \
                strerror strstr])dnl

dnl# Output.
AC_CONFIG_FILES([Makefile
           debug/Makefile
           authentication/Makefile
           mdnsd/Makefile
           opendaap.pc])
AC_OUTPUT
