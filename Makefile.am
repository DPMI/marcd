ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = 

if BUILD_DAEMON
bin_PROGRAMS += MArCd
endif

if BUILD_RELAY
bin_PROGRAMS += MArelayD
endif

MArCd_CXXFLAGS = -Wall -pthread ${MYSQL_CLIENT_CFLAGS} ${libmarc_CFLAGS} ${RRDTOOL_CFLAGS}
MArCd_LDADD = ${MYSQL_CLIENT_LIBS} ${libmarc_LIBS} ${RRDTOOL_LIBS}
MArCd_SOURCES = \
	daemon.cpp daemon.h \
	database.cpp database.h \
	control.cpp control.h \
	relay.cpp relay.h \
	status.cpp \
	utils.cpp utils.h \
	main.cpp

MArelayD_CXXFLAGS = -Wall -DBUILD_RELAY ${libmarc_CFLAGS}
MArelayD_LDADD = ${libmarc_LIBS}
MArelayD_SOURCES = relay.cpp

install-exec-hook:
	install -d ${DESTDIR}${pkgdatadir}
