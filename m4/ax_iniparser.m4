AC_DEFUN([AX_INIPARSER], [
  AH_TEMPLATE([HAVE_INIPARSER_H], [Define to 1 if iniparser library is available])
  AC_ARG_WITH([iniparser], [AS_HELP_STRING([--with-iniparser=DIR], [Support for ini-style configuration files using iniparser @<:@default=enabled@:>@])],, [with_iniparser=no])
  case $with_iniparser in
    no)
      ax_iniparser_want=no
      ax_iniparser_path=
      ;;
    yes|"")
      ax_iniparser_want=yes
      ax_iniparser_path=
      ;;
    *)
      ax_iniparser_want=yes
      ax_iniparser_path="$withval"
      ;;
  esac
  AS_IF([test "x$ax_iniparser_want" == "xyes"], [
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LDFLAGS="$LDFLAGS"
    CPPFLAGS="$CPPFLAGS -I$ax_iniparser_path/include"
    LDFLAGS="$LDFLAGS -L$ax_iniparser_path/lib"
    AC_CHECK_HEADER([iniparser.h],,[
      AC_MSG_ERROR([Required library iniparser not found])
    ])
    AC_CHECK_LIB([iniparser], [iniparser_load],, [
      AC_MSG_ERROR([Required library iniparser not found])
    ])

    if test "x$ax_iniparser_path" != "x"; then
      AC_SUBST(iniparser_CFLAGS, [-I$ax_iniparser_path/include])
      AC_SUBST(iniparser_LIBS, ["-L$ax_iniparser_path/lib -liniparser"])
    else
      AC_SUBST(iniparser_CFLAGS, [])
      AC_SUBST(iniparser_LIBS, [-liniparser])
    fi
    AC_DEFINE([HAVE_INIPARSER_H])

    LDFLAGS="$saved_LDFLAGS"
    CPPFLAGS="$saved_CPPFLAGS"
  ])
])
