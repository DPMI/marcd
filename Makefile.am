ACLOCAL_AMFLAGS = -I m4

noinst_LIBRARIES = libcommon.a libstatus.a
bin_PROGRAMS = 
EXTRA_DIST = marcd.conf.dist

if BUILD_DAEMON
bin_PROGRAMS += MArCd
endif

if BUILD_RELAY
bin_PROGRAMS += MArelayD
endif

pkgconf_DATA = marcd.conf.dist

# shades sources
libcommon_a_SOURCES = src/globals.cpp src/globals.hpp src/log.cpp src/log.hpp

# src/status.cpp needs special CXXFLAGS because of the way it interacts with rrdtool (not const correct)
libstatus_a_SOURCES = src/status.cpp
libstatus_a_CXXFLAGS = ${AM_CXXFLAGS} -Wall -pthread ${MYSQL_CLIENT_CFLAGS} ${libcap_marc_CFLAGS} ${RRDTOOL_CFLAGS} ${iniparser_CFLAGS} -Wno-write-strings

MArCd_CXXFLAGS = ${AM_CXXFLAGS}  -Wall -pthread ${MYSQL_CLIENT_CFLAGS} ${libcap_marc_CFLAGS} ${RRDTOOL_CFLAGS} ${iniparser_CFLAGS}
MArCd_LDADD = libcommon.a libstatus.a ${MYSQL_CLIENT_LIBS} ${libcap_marc_LIBS} ${libcap_utils_LIBS} ${RRDTOOL_LIBS} ${iniparser_LIBS}
MArCd_SOURCES = \
	src/daemon.cpp src/daemon.hpp \
	src/database.cpp src/database.hpp \
	src/control.cpp src/control.hpp \
	src/relay.cpp src/relay.hpp \
	src/utils.cpp src/utils.hpp \
	src/main.cpp

if HAVE_INIPARSER
MArCd_SOURCES += src/configfile.cpp src/configfile.hpp
endif

if BUNDLE_INIPARSER
MArCd_SOURCES += bundle/iniparser.c bundle/iniparser.h bundle/dictionary.c bundle/dictionary.h
endif

MArelayD_CXXFLAGS = -Wall -DBUILD_RELAY ${libcap_marc_CFLAGS}
MArelayD_LDADD = libcommon.a ${libcap_utils_LIBS}
MArelayD_SOURCES = src/relay.cpp

BUILT_SOURCES = vcs.h
CLEANFILES = vcs.h
if HAVE_VCS
.PHONY: .vcs
BUILT_SOURCES += .vcs vcs.h stamp-vcs
CLEANFILES += .vcs stamp-vcs
.vcs: Makefile
	@git rev-parse --short HEAD | sed 's/\(.*\)/#define VCS_REV "\1"/' > .vcs
	@git rev-parse --abbrev-ref HEAD | sed 's/\(.*\)/#define VCS_BRANCH "\1"/' >> .vcs
	@cmp -s vcs.h .vcs || touch stamp-vcs
stamp-vcs: .vcs
vcs.h: stamp-vcs
	$(AM_V_GEN)cp .vcs vcs.h
else
vcs.h: Makefile
	@echo -n > vcs.h
endif
MArCd_SOURCES += vcs.h

install-exec-hook:
	install -d ${DESTDIR}${pkgdatadir}

version=@VERSION@
debversion=`echo $(version) | sed 's/_//'`
debpkgname=marcd_${debversion}_@ARCH@

deb: all
	@test "x"`id -u` = "x0" || (echo "Must be root when executing \"make deb\" to set proper permissions"; exit 1)
	@test "x${prefix}" = "x/usr" || (echo "Error: --prefix must be /usr when creating debian release (currently ${prefix})"; exit 1)
	@test "x${sysconfdir}" = "x/etc" || (echo "Error: --sysconfdir must be /etc when creating debian release (currently ${sysconfdir})"; exit 1)
	@test "x${localstatedir}" = "x/var/lib" || (echo "Error: --localstatedir must be /var/lib when creating debian release (currently ${localstatedir})"; exit 1)
	rm -rf $(debpkgname)

	mkdir -p $(debpkgname)/DEBIAN
	mkdir -p $(debpkgname)/$(pkgdatadir) && chmod 0755 $(debpkgname)/$(pkgdatadir)
	mkdir -p $(debpkgname)/$(pkgconfdir) && chmod 0755 $(debpkgname)/$(pkgconfdir)
	mkdir -p $(debpkgname)/etc/default && chmod 0755 $(debpkgname)/etc/default
	mkdir -p $(debpkgname)/etc/init.d  && chmod 0755 $(debpkgname)/etc/init.d
	cp dist/deb-control $(debpkgname)/DEBIAN/control
	$(MAKE) install DESTDIR=`pwd`/$(debpkgname)
	install -m 0755 -o root -g root ${top_srcdir}/dist/deb-postinst ${debpkgname}/DEBIAN/postinst
	install -m 0755 -o root -g root ${top_srcdir}/dist/deb-postrm ${debpkgname}/DEBIAN/postrm
	install -m 0755 -o root -g root $(top_srcdir)/dist/debian-conf $(debpkgname)/etc/default/marcd
	install -m 0755 -o root -g root $(top_srcdir)/dist/debian-init $(debpkgname)/etc/init.d/marcd
	echo "/etc/default/marcd" > $(debpkgname)/DEBIAN/conffiles
	chmod 0755 $(debpkgname)/usr/bin/MArCd
	chmod 0755 $(debpkgname)/usr/bin/MArelayD
	strip $(debpkgname)/usr/bin/MArCd
	strip $(debpkgname)/usr/bin/MArelayD
	(cd $(debpkgname); find . -type f ! -regex '.*.hg.*' ! -regex '.*?debian-binary.*' ! -regex '.*?DEBIAN.*' -printf '%P ' | xargs md5sum > DEBIAN/md5sums)
	dpkg-deb --build $(debpkgname)
