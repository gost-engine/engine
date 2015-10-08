AC_PREREQ([2.69])
AC_INIT([gost-engine], [1.0])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

m4_include([m4/ax_check_openssl.m4])

AC_ARG_VAR([OPENSSL_SRCDIR],[Set the folder containing OpenSSL source.  Not mandatory])

AM_INIT_AUTOMAKE
LT_INIT([disable-static pic-only])

AC_PROG_CC
AC_LANG(C)

AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h])

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_FUNCS([memmove memset])

AX_CHECK_OPENSSL(
  [have_openssl=yes],
  [AC_MSG_FAILURE([could not locate OpenSSL])]
)

if test "x$have_openssl" = "xyes"; then
  LIBS="$LIBS $OPENSSL_LIBS"
  CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
  LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
fi

AC_SUBST([OPENSSL_SRCDIR])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
