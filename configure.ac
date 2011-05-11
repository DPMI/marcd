AC_INIT([MArCd],[0.7.1], [dsv@bth.se])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 silent-rules foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CXX
AC_GNU_SOURCE
MYSQL_CLIENT
AX_RRDTOOL

pkgdatadir="${localstatedir}/lib/marc"
AC_SUBST(pkgdatadir)
AX_DEFINE_DIR([DATA_DIR], [pkgdatadir], [Directory where datafiles are stored])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([libmarc], [libmarc >= 0.7])

AC_OUTPUT
