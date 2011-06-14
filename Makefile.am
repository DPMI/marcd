ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = 

if BUILD_DAEMON
bin_PROGRAMS += MArCd
endif

if BUILD_RELAY
bin_PROGRAMS += MArelayD
endif

MArCd_CXXFLAGS = -Wall ${MYSQL_CLIENT_CFLAGS} ${libmarc_CFLAGS} ${RRDTOOL_CFLAGS}
MArCd_LDADD = ${MYSQL_CLIENT_LIBS} ${libmarc_LIBS} ${RRDTOOL_LIBS}
MArCd_SOURCES = main.cpp status.cpp

MArelayD_CXXFLAGS = -Wall
MArelayD_SOURCES = relay.cpp

install-exec-hook:
	install -d ${DESTDIR}${pkgdatadir}
