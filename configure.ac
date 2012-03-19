AC_INIT([MArCd],[0.7.6], [dsv@bth.se])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 foreign check-news])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CXX
AC_PROG_RANLIB
AC_GNU_SOURCE
PKG_PROG_PKG_CONFIG
AC_SEARCH_LIBS([clock_gettime], [rt])
AX_INIPARSER
AC_ARG_PROGRAM

AC_ARG_ENABLE([daemon], [AS_HELP_STRING([--enable-daemon], [Build MArCd @<:@default=enabled@:>@])])
AC_ARG_ENABLE([relay],  [AS_HELP_STRING([--enable-relay],  [Build MArelayD @<:@default=enabled@:>@])])

pkgdatadir="${localstatedir}/marc"
pkgconfdir="${sysconfdir}/marc"
AC_SUBST(pkgdatadir)
AC_SUBST(pkgconfdir)
AX_DEFINE_DIR([DATA_DIR], [pkgdatadir], [Directory where datafiles are stored])
AX_DEFINE_DIR([SYSCONF_DIR], [pkgconfdir], [installation directory for read-only signle-machine data])

AS_IF([test "x$with_daemon" != "xno"], [
	MYSQL_CLIENT
	AX_RRDTOOL
	PKG_CHECK_MODULES([libcap_filter], [libcap_filter-0.7 >= 0.7.4])
	PKG_CHECK_MODULES([libcap_marc], [libcap_marc-0.7 >= 0.7.4])
])
AM_CONDITIONAL(BUILD_DAEMON, [test "x$enable_daemon" != "xno"])
AM_CONDITIONAL(BUILD_RELAY,  [test "x$enable_relay" != "xno"])

AC_ARG_WITH([syslog], [AS_HELP_STRING([--with-syslog], [Build support for syslog @<:@default=enabled@:>@])])
AS_IF([test "x$with_syslog" != "xno"], [
  AC_CHECK_FUNCS([syslog])
  AS_IF([test "x$ac_cv_func_syslog" != "xyes"], [AC_MSG_ERROR([syslog support requested but syslog function not found. Either ensure syslog is available or use --without-syslog to disable.])])
])

AC_DEFINE([MA_CONTROL_DEFAULT_PORT], [1600], [Which port MArCd should listen on])
AC_DEFINE([MA_RELAY_DEFAULT_PORT], [1500], [Which port MArelayD should listen on])

AC_OUTPUT
