ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = 
EXTRA_DIST = marcd.conf.dist

if BUILD_DAEMON
bin_PROGRAMS += MArCd
endif

if BUILD_RELAY
bin_PROGRAMS += MArelayD
endif

pkgconf_DATA = marcd.conf.dist

MArCd_CXXFLAGS = -Wall -pthread ${MYSQL_CLIENT_CFLAGS} ${libcap_marc_CFLAGS} ${RRDTOOL_CFLAGS} ${iniparser_CFLAGS}
MArCd_LDADD = ${MYSQL_CLIENT_LIBS} ${libcap_marc_LIBS} ${libcap_utils_LIBS} ${RRDTOOL_LIBS} ${iniparser_LIBS}
MArCd_SOURCES = \
	src/daemon.cpp src/daemon.hpp \
	src/database.cpp src/database.hpp \
	src/control.cpp src/control.hpp \
	src/relay.cpp src/relay.hpp \
	src/status.cpp \
	src/utils.cpp src/utils.hpp \
	src/log.cpp src/log.hpp \
	src/main.cpp

if BUNDLE_INIPARSER
MArCd_SOURCES += bundle/iniparser.c bundle/iniparser.h bundle/dictionary.c bundle/dictionary.h
endif

MArelayD_CXXFLAGS = -Wall -DBUILD_RELAY ${libcap_marc_CFLAGS}
MArelayD_LDADD = ${libcap_marc_LIBS} ${libcap_filter_LIBS}
MArelayD_SOURCES = src/relay.cpp src/log.cpp src/log.hpp

install-exec-hook:
	install -d ${DESTDIR}${pkgdatadir}

version=@VERSION@
debversion=`echo $(version) | sed 's/_//'`
debpkgname=marcd_${debversion}_@ARCH@

deb: all
	@test "x${prefix}" = "x/usr" || (echo "Error: --prefix must be /usr when creating debian release (currently ${prefix})"; exit 1)
	@test "x${sysconfdir}" = "x/etc" || (echo "Error: --sysconfdir must be /etc when creating debian release (currently ${sysconfdir})"; exit 1)
	@test "x${localstatedir}" = "x/var/lib" || (echo "Error: --localstatedir must be /var/lib when creating debian release (currently ${localstatedir})"; exit 1)

	mkdir -p $(debpkgname)/DEBIAN
	mkdir -p $(debpkgname)/$(pkgdatadir) && chmod 0755 $(debpkgname)/$(pkgdatadir)
	mkdir -p $(debpkgname)/$(pkgconfdir) && chmod 0755 $(debpkgname)/$(pkgconfdir)
	cp dist/deb-control $(debpkgname)/DEBIAN/control
	cp $(top_srcdir)/dist/debian-init $(debpkgname)/DEBIAN/marcd.init
	$(MAKE) install DESTDIR=`pwd`/$(debpkgname)
	strip $(debpkgname)/usr/bin/MArCd
	strip $(debpkgname)/usr/bin/MArelayD
	dpkg-deb --build $(debpkgname)
