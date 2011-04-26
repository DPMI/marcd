AC_INIT([MArCd],[0.7], [dsv@bth.se])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 silent-rules foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CXX
AC_GNU_SOURCE
MYSQL_CLIENT

PKG_CHECK_MODULES([libmarc], [libmarc >= 0.5])

AC_OUTPUT
