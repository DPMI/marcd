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

MArCd_CXXFLAGS = -Wall -pthread ${MYSQL_CLIENT_CFLAGS} ${libcap_marc_CFLAGS} ${RRDTOOL_CFLAGS}
MArCd_LDADD = ${MYSQL_CLIENT_LIBS} ${libcap_marc_LIBS} ${libcap_utils_LIBS} ${RRDTOOL_LIBS}
MArCd_SOURCES = \
	src/daemon.cpp src/daemon.hpp \
	src/database.cpp src/database.hpp \
	src/control.cpp src/control.hpp \
	src/relay.cpp src/relay.hpp \
	src/status.cpp \
	src/utils.cpp src/utils.hpp \
	src/log.cpp src/log.hpp \
	src/main.cpp

MArelayD_CXXFLAGS = -Wall -DBUILD_RELAY ${libcap_marc_CFLAGS}
MArelayD_LDADD = ${libcap_marc_LIBS} ${libcap_filter_LIBS}
MArelayD_SOURCES = src/relay.cpp src/log.cpp src/log.hpp

install-exec-hook:
	install -d ${DESTDIR}${pkgdatadir}

debpkgname=marcd_@VERSION@_@ARCH@

deb: all
	@test "x${prefix}" = "x/usr" || (echo "Error: --prefix must be /usr when creating debian release (currently ${prefix})"; exit 1)
	@test "x${sysconfdir}" = "x/etc" || (echo "Error: --sysconfdir must be /etc when creating debian release (currently ${sysconfdir})"; exit 1)
	@test "x${localstatedir}" = "x/var/lib" || (echo "Error: --localstatedir must be /var/lib when creating debian release (currently ${localstatedir})"; exit 1)

	mkdir -p $(debpkgname)/DEBIAN
	mkdir -p $(debpkgname)/$(pkgdatadir)
	mkdir -p $(debpkgname)/$(pkgconfdir)
	cp dist/deb-control $(debpkgname)/DEBIAN/control
	$(MAKE) install DESTDIR=`pwd`/$(debpkgname)
	dpkg-deb --build $(debpkgname)
