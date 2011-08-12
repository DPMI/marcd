AC_INIT([MArCd],[0.7.3], [dsv@bth.se])

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
AC_SEARCH_LIBS([clock_gettime], [rt])
AX_INIPARSER

AC_ARG_ENABLE([daemon], [AS_HELP_STRING([--enable-daemon], [Build MArCd @<:@default=enabled@:>@])])
AC_ARG_ENABLE([relay],  [AS_HELP_STRING([--enable-relay],  [Build MArelayD @<:@default=enabled@:>@])])

pkgdatadir="${localstatedir}/lib/marc"
AC_SUBST(pkgdatadir)
AX_DEFINE_DIR([DATA_DIR], [pkgdatadir], [Directory where datafiles are stored])
AX_DEFINE_DIR([SYSCONF_DIR], [sysconfdir], [installation directory for read-only signle-machine data])

AS_IF([test "x$with_daemon" != "xno"], [
	MYSQL_CLIENT
	AX_RRDTOOL
	PKG_CHECK_MODULES([libmarc], [libmarc >= 0.7.1])
])
AM_CONDITIONAL(BUILD_DAEMON, [test "x$enable_daemon" != "xno"])
AM_CONDITIONAL(BUILD_RELAY,  [test "x$enable_relay" != "xno"])


AC_DEFINE([MA_CONTROL_DEFAULT_PORT], [1600], [Which port MArCd should listen on])
AC_DEFINE([MA_RELAY_DEFAULT_PORT], [1500], [Which port MArelayD should listen on])

AC_OUTPUT
