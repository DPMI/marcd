/**
* Measurement Area Control Daemon
* Copyright (C) 2003-2013 (see AUTHORS)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "database.hpp"
#include "log.hpp"
#include <caputils/marc.h>
#include <caputils/log.h>

#ifdef HAVE_RRDTOOL
#include <rrd.h>
#endif

#define RRD_HEARTBEAT "180"    /* can miss two updates */

#include <cstring>
#include <cassert>
#include <cerrno>
#include <sys/types.h>
#include <sys/stat.h>

extern char* rrdpath;

#ifdef HAVE_RRDTOOL
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

template <class T>
static const char* join_cmd(char* dst, int argc, T* argv[]){
	char* ptr = dst;
	ptr += sprintf(ptr, "rrdtool");
	for ( int i = 0; i < argc; i++ ){
		ptr += sprintf(ptr, " '%s'", argv[i]);
	}
	return dst;
}

static void update(const char* when, const char* MAMPid, int CI, long packets, long matched, long dropped, int BU, const char* iface[]){
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

	char v3[22] = "U"; /* fits a 64-bit int */
	if ( dropped >= 0 ){
		snprintf(v3, sizeof(v3), "%ld", dropped);
	}

	char v4[16] = "U";
	if ( BU >= 0 ){
		snprintf(v4, sizeof(v4), "%.1f", (float)BU/10);
	}

	snprintf(update, 1024, "%s:%s:%s:%s:%s", when, v1, v2, v3, v4);

	char buffer[1024];
	unsigned int argc = sizeof(argv) / sizeof(char*);
	Log::verbose("status", "    Executing \"%s\"\n", join_cmd(buffer, argc, argv));

	rrd_clear_error();
	if ( rrd_update(argc, argv) < 0 ){
		Log::fatal("status", "    rrd_update() failed: %s\n", rrd_get_error());
	}

	free(filename);
}

static void reset(const char* MAMPid, int noCI, const char* iface[]){
	Log::verbose("status", "Resetting RRD counters for %s (%d CI)\n", MAMPid, noCI);
	update("-1", MAMPid, -1, -1, -1, -1, -1, iface);
	update("N", MAMPid, -1, 0, 0, 0, 0, iface);

	for ( int i=0; i < noCI; i++ ){
		update("-1", MAMPid, i, -1, -1, -1, -1, iface);
		update("N", MAMPid, i, 0, 0, 0, 0, iface);
	}
}
#endif /* HAVE_RRDTOOL */

struct MPstatusExtended* unpack_status_legacy(const struct MPstatusLegacyExt* old){
	static struct MPstatusExtended* s = NULL;
	static unsigned int noCI = 0;

	/* reallocate as needed */
	if ( !s || old->noCI > noCI ){
		noCI = old->noCI;
		s = (struct MPstatusExtended*)realloc(s, sizeof(struct MPstatusExtended) + sizeof(struct CIstats) * noCI);
	}

	s->type = old->type;
	memcpy(s->MAMPid, old->MAMPid, 8);
	s->version = 0;
	s->packet_count = ntohl(old->packet_count);
	s->matched_count = ntohl(old->matched_count);
	s->dropped_count = 0;
	s->status = old->status;
	s->noFilters = old->noFilters;
	s->noCI = old->noCI;

	for ( int i = 0; i < old->noCI; i++ ){
		memcpy(s->CI[i].iface, old->CI[i].iface, 8);
		s->CI[i].packet_count = ntohl(old->CI[i].packet_count);
		s->CI[i].matched_count = ntohl(old->CI[i].matched_count);
		s->CI[i].dropped_count = 0;
		s->CI[i].buffer_usage = ntohl(old->CI[i].buffer_usage);
	}

	return s;
}

struct MPstatusExtended* unpack_status(struct MPstatusExtended* s){
	s->packet_count = ntohl(s->packet_count);
	s->matched_count = ntohl(s->matched_count);
	s->dropped_count = ntohl(s->dropped_count);

	/* conver to latest (supported) version */
	switch ( s->version ){
	case 1:
		s->MTU = 0;

	case 2:
		s->MTU = ntohs(s->MTU);
	}

	for ( int i = 0; i < s->noCI; i++ ){
		s->CI[i].packet_count = ntohl(s->CI[i].packet_count);
		s->CI[i].matched_count = ntohl(s->CI[i].matched_count);
		s->CI[i].dropped_count = ntohl(s->CI[i].dropped_count);
		s->CI[i].buffer_usage = ntohl(s->CI[i].buffer_usage);
	}

	return s;
}

void MP_Status(marc_context_t marc, struct MPstatusExtended* MPstat, struct sockaddr* from){
	assert(MPstat);
	assert(from);

	const char* mampid = mampid_get(MPstat->MAMPid);

	/* update MP MTU */
	if ( MPstat->MTU > 0 ){
		db_query("UPDATE `measurementpoints` SET `MTU` = %d WHERE `mampid` = '%s'", MPstat->MTU, mampid);
	}

	Log::verbose("status", "Extended status from %s:%d (MAMPid: %s, version: %d)\n",
	             inet_ntoa(((struct sockaddr_in*)from)->sin_addr), ntohs(((struct sockaddr_in*)from)->sin_port), mampid, MPstat->version);

	/* bump timestamp */ {
		char buf[16*2+1]; /* mampids are 16 bytes, worst-case escape requires n*2 chars + nullterminator */
		mysql_real_escape_string(&connection, buf, mampid_get(MPstat->MAMPid), strlen(MPstat->MAMPid));
		db_query("UPDATE measurementpoints SET time = CURRENT_TIMESTAMP, status = %d WHERE MAMPid = '%s'", MPstat->noFilters > 0 ? 2 : 1, buf);
	}

#ifdef HAVE_RRDTOOL
	const char* iface[MPstat->noCI];
	for (int i=0; i < MPstat->noCI; i++ ){
		iface[i] = MPstat->CI[i].iface;
	}

	update("N", mampid, -1,
	       MPstat->packet_count,
	       MPstat->matched_count,
	       MPstat->dropped_count,
	       0, iface);

	for (int i=0; i < MPstat->noCI; i++ ){
		update("N", mampid, i,
		       MPstat->CI[i].packet_count,
		       MPstat->CI[i].matched_count,
		       MPstat->CI[i].dropped_count,
		       MPstat->CI[i].buffer_usage,
		       iface);
	}
#endif /* HAVE_RRDTOOL */
}

#ifdef HAVE_RRDTOOL
static void create(const char* mampid, int CI, const char* iface[]){
	char* filename = table_name(mampid, CI, iface);
	char* argv[] = {
		"create", filename,
		"--step", "60",
		"DS:total:COUNTER:180:0:U",
		"DS:matched:COUNTER:180:0:U",
		"DS:dropped:COUNTER:180:0:U",
		"DS:BU:GAUGE:180:0:100",
		"RRA:AVERAGE:0.5:1:1440",    "RRA:MAX:0.5:1:1440",     /* 1 min resolution,  1440 points * 60s = 24h */
		"RRA:AVERAGE:0.5:60:1440",   "RRA:MAX:0.5:60:1440",    /* 1 hour resolution, 1440 points * 60s * 60 samples per point = 60 days */
		"RRA:AVERAGE:0.5:1440:720",  "RRA:MAX:0.5:1440:720",   /* 24 hour resolution, 720 points * 60s * 1440 samples per point = 5 years */
	};

	struct stat st;
	if ( stat(filename, &st) == 0 ){
		return; /* file exists */
	}
	Log::verbose("status", "Creating RRD table `%s'.\n", filename);

	char buffer[1024];
	unsigned int argc = sizeof(argv) / sizeof(char*);
	Log::verbose("status", "    Executing \"%s\"\n", join_cmd(buffer, argc, argv));

	rrd_clear_error();
	if ( rrd_create(argc, (char**)argv) < 0 ){
		Log::fatal("status", "    rrd_create() failed: %s\n", rrd_get_error());
	}

	free(filename);
}
#endif /* HAVE_RRDTOOL */

void setup_rrd_tables(const char* mampid, unsigned int noCI, const char* iface[]){
#ifndef HAVE_RRDTOOL
	return;
#else

	/* create RRD tables as needed */
	create(mampid, -1, iface);
	for ( unsigned int i = 0; i < noCI; i++ ){
		create(mampid, i, iface);
	}

	/* reset status counters */
	reset(mampid, noCI, iface);
#endif
}
