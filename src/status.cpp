#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "log.hpp"
#include <caputils/marc.h>
#include <caputils/log.h>

#ifdef HAVE_RRDTOOL
#include <rrd.h>
#endif

#define RRD_HEARTBEAT "180"    /* can miss two updates */

#include <cassert>
#include <cerrno>
#include <sys/types.h>
#include <sys/stat.h>

extern char* rrdpath;

static char* table_name(const char* mampid, int CI, const char* iface[]){
	char* buf;
	int ret;
	if ( CI >= 0 ){
		ret=asprintf(&buf, "%s/%s_%s.rrd", rrdpath, mampid, iface[CI]);
	} else {
		ret=asprintf(&buf, "%s/%s.rrd", rrdpath, mampid);
	}
	if ( ret == -1 ){
		Log::fatal("status", "asprintf(..) returned -1: %s\n", strerror(errno));
	}
	return buf;
}

static const char* join_cmd(char* dst, int argc, char* argv[]){
	char* ptr = dst;
	ptr += sprintf(ptr, "rrdtool");
	for ( int i = 0; i < argc; i++ ){
		ptr += sprintf(ptr, " '%s'", argv[i]);
	}
	return dst;
}

#ifdef HAVE_RRDTOOL
static void update(const char* when, const char* MAMPid, int CI, long packets, long matched, const char* iface[]){
	assert(when);
	assert(MAMPid);

	static char cmd[] = "update";
	static char separator[] = "--";
	char* filename = table_name(MAMPid, CI, iface);
	char update[1024];
	char* argv[] = {
		cmd,
		filename,
		separator,
		update
	};

	char v1[22] = "U"; /* fits a 64-bit int */
	if ( packets >= 0 ){
		snprintf(v1, 22, "%ld", packets);
	}

	char v2[22] = "U"; /* fits a 64-bit int */
	if ( matched >= 0 ){
		snprintf(v2, 22, "%ld", matched);
	}

	snprintf(update, 1024, "%s:%s:%s", when, v1, v2);

	char buffer[1024];
	unsigned int argc = sizeof(argv) / sizeof(char*);
	Log::verbose("status", "    Executing \"%s\"\n", join_cmd(buffer, argc, argv));

	rrd_clear_error();
	if ( rrd_update(argc, argv) < 0 ){
		Log::fatal("status", "    rrd_update() failed: %s\n", rrd_get_error());
	}

	free(filename);
}
#endif /* HAVE_RRDTOOL */

static void reset(const char* MAMPid, int noCI, const char* iface[]){
#ifdef HAVE_RRDTOOL
	Log::verbose("status", "Resetting RRD counters for %s\n", MAMPid);
	update("-1", MAMPid, -1, -1, -1, iface);
	update("N", MAMPid, -1, 0, 0, iface);

	for ( int i=0; i < noCI; i++ ){
		update("-1", MAMPid, i, -1, -1, iface);
		update("N", MAMPid, i, 0, 0, iface);
	}
#endif /* HAVE_RRDTOOL */
}

void MP_Status2(marc_context_t marc, MPstatus2* MPstat, struct sockaddr* from){
	assert(MPstat);
	assert(from);

	const char* mampid = mampid_get(MPstat->MAMPid);

	Log::verbose("status", "Extended status from %s:%d (MAMPid: %s)\n",
	             inet_ntoa(((struct sockaddr_in*)from)->sin_addr), ntohs(((struct sockaddr_in*)from)->sin_port), mampid);

#ifdef HAVE_RRDTOOL
	const char* iface[MPstat->noCI];
	for (int i=0; i < MPstat->noCI; i++ ){
		iface[i] = MPstat->CI[i].iface;
	}

	update("N", mampid, -1, ntohl(MPstat->packet_count), ntohl(MPstat->matched_count), iface);

	for (int i=0; i < MPstat->noCI; i++ ){
		update("N", mampid, i, ntohl(MPstat->CI[i].packet_count), ntohl(MPstat->CI[i].matched_count), iface);
	}
#endif /* HAVE_RRDTOOL */
}

static void create(const char* mampid, int CI, const char* iface[]){
	char* filename = table_name(mampid, CI, iface);
	const char* argv[] = {
		"create", filename,
		"--step", "60",
		"DS:total:COUNTER:180:0:U",
		"DS:matched:COUNTER:180:0:U",
		"RRA:AVERAGE:0.5:1:1440",      /* 1440 * 60s = 24h */
		"RRA:AVERAGE:0.5:30:1440",     /* 1440 * 60s * 30 = 30 days */
	};

	struct stat st;
	if ( stat(filename, &st) == 0 ){
		return; /* file exists */
	}
	Log::verbose("status", "Creating RRD table `%s'.\n", filename);

	char buffer[1024];
	unsigned int argc = sizeof(argv) / sizeof(char*);
	Log::verbose("status", "    Executing \"%s\"\n", join_cmd(buffer, argc, (char**)argv));

	rrd_clear_error();
	if ( rrd_create(argc, (char**)argv) < 0 ){
		Log::fatal("status", "    rrd_create() failed: %s\n", rrd_get_error());
	}

	free(filename);
}

void setup_rrd_tables(const char* mampid, unsigned int noCI, const char* iface[]){
#ifndef HAVE_RRDTOOL
	return;
#endif

	/* create RRD tables as needed */
	create(mampid, -1, iface);
	for ( unsigned int i = 0; i < noCI; i++ ){
		create(mampid, i, iface);
	}

	/* reset status counters */
	reset(mampid, noCI, iface);
}
