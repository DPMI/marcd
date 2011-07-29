AC_INIT([MArCd],[0.7.2], [dsv@bth.se])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 foreign])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CXX
AC_PROG_RANLIB
AC_GNU_SOURCE
PKG_PROG_PKG_CONFIG

AC_ARG_WITH([daemon], [AS_HELP_STRING([--with-daemon], [Build MArCd @<:@default=enabled@:>@])])
AC_ARG_WITH([relay],  [AS_HELP_STRING([--with-relay],  [Build MArelayD @<:@default=enabled@:>@])])

pkgdatadir="${localstatedir}/lib/marc"
AC_SUBST(pkgdatadir)
AX_DEFINE_DIR([DATA_DIR], [pkgdatadir], [Directory where datafiles are stored])

AS_IF([test "x$with_daemon" != "xno"], [
	MYSQL_CLIENT
	AX_RRDTOOL
	PKG_CHECK_MODULES([libmarc], [libmarc >= 0.7])
])
AM_CONDITIONAL(BUILD_DAEMON, [test "x$with_daemon" != "xno"])
AM_CONDITIONAL(BUILD_RELAY,  [test "x$with_relay" != "xno"])

AC_DEFINE([MA_CONTROL_DEFAULT_PORT], [1600], [Which port MArCd should listen on])
AC_DEFINE([MA_RELAY_DEFAULT_PORT], [1500], [Which port MArelayD should listen on])

AC_OUTPUT
