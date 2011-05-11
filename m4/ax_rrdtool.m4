AC_DEFUN([AX_RRDTOOL], [
  AH_TEMPLATE([HAVE_RRDTOOL], [Define if rrdtool library is available])
  AC_ARG_WITH([rrdtool], [AS_HELP_STRING([--with-rrdtool=DIR], [Enable support for rrdtool @<:@default=enabled@:>@])])
  case $with_rrdtool in
    no)
      ax_rrdtool_want=no
      ax_rrdtool_path=
      ;;    
    yes | "")
      ax_rrdtool_want=yes
      ax_rrdtool_path=
      ;;
    *)
      ax_rrdtool_want=yes
      ax_rrdtool_path="$withval"
      ;;
  esac
  if test "x$ax_rrdtool_want" == "xyes"; then
    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -I$ax_rrdtool_path/include"
    AC_CHECK_HEADER([rrd.h],[
      saved_LDFLAGS="$LDFLAGS"
      LDFLAGS="$LDFLAGS -L$ax_rrdtool_path/lib"
      AC_CHECK_LIB([rrd], [rrd_update], [
        if test "x$ax_rrdtool_path" != "x"; then
	  AC_SUBST(RRDTOOL_CFLAGS, [-I$ax_rrdtool_path/include])
          AC_SUBST(RRDTOOL_LIBS, ["-L$ax_rrdtool_path/lib -lrrd"])
        else
	  AC_SUBST(RRDTOOL_CFLAGS, [])
          AC_SUBST(RRDTOOL_LIBS, [-lrrd])
	fi
	AC_DEFINE([HAVE_RRDTOOL])
      ], [
        AC_MSG_ERROR([Required library rrdtool not found])
      ])
      LDFLAGS="$saved_LDFLAGS"
    ], [
      AC_MSG_ERROR([Required library rrdtool not found])
    ])
    CPPFLAGS="$saved_CPPFLAGS"
  fi
])
