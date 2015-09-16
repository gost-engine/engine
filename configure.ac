AC_PREREQ(2.63)
AC_INIT([libgost],[1.0.2],[openssl-gost@lists.wagner.pp.ru])
AC_CONFIG_SRCDIR([./gost_eng.c])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])
LT_INIT

ENGINEDIR=$libdir/ssl/engines
AC_ARG_WITH([enginedir],
	[AS_HELP_STRING([--with-enginedir],[specify location of OpenSSL engines])],
	[ENGINEDIR="$withval"])
AC_SUBST(ENGINEDIR)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_CHECK_PROG([PERL],[perl],[perl],[AC_MSG_ERROR([*** perl not found])])
# Checks for libraries.
AC_CHECK_LIB([crypto], [ENGINE_new], [], [AC_MSG_ERROR([*** libcrypto not       found])]) 
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
