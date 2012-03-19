ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = 
EXTRA_DIST = marcd.conf.dist

if BUILD_DAEMON
bin_PROGRAMS += MArCd
endif

if BUILD_RELAY
bin_PROGRAMS += MArelayD
endif

sysconf_DATA = marcd.conf.dist

MArCd_CXXFLAGS = -Wall -pthread ${MYSQL_CLIENT_CFLAGS} ${libcap_marc_CFLAGS} ${RRDTOOL_CFLAGS}
MArCd_LDADD = ${MYSQL_CLIENT_LIBS} ${libcap_marc_LIBS} ${libcap_filter_LIBS} ${RRDTOOL_LIBS}
MArCd_SOURCES = \
	daemon.cpp daemon.h \
	database.cpp database.h \
	control.cpp control.h \
	relay.cpp relay.h \
	status.cpp \
	utils.cpp utils.h \
	log.cpp log.h \
	main.cpp

MArelayD_CXXFLAGS = -Wall -DBUILD_RELAY ${libcap_marc_CFLAGS}
MArelayD_LDADD = ${libcap_marc_LIBS}
MArelayD_SOURCES = relay.cpp

install-exec-hook:
	install -d ${DESTDIR}${pkgdatadir}
