#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "log.h"
#include <caputils/marc.h>
#include <caputils/log.h>

#ifdef HAVE_RRDTOOL
#include <rrd.h>
#endif

#include <cassert>

extern char* rrdpath;

#ifdef HAVE_RRDTOOL
static void update(char* b1, char* b2, const char* when, const char* MAMPid, int CI, long packets, long matched){
  assert(b1);
  assert(b2);
  assert(when);
  assert(MAMPid);

  static char cmd[] = "update";
  static char separator[] = "--";
  char* argv[] = {
    cmd,
    b1,
    separator,
    b2
  };

  if ( CI >= 0 ){
    snprintf(b1, 1024, "%s/%s_CI%d.rrd", rrdpath, MAMPid, CI);
  } else {
    snprintf(b1, 1024, "%s/%s.rrd", rrdpath, MAMPid);
  }

  char v1[22] = "U"; /* fits a 64-bit int */
  if ( packets > 0 ){
    snprintf(v1, 22, "%ld", packets);
  }

  char v2[22] = "U"; /* fits a 64-bit int */
  if ( matched > 0 ){
    snprintf(v2, 22, "%ld", matched);
  }

  snprintf(b2, 1024, "%s:%s:%s", when, v1, v2);

  unsigned int argc = 4;
  char buffer[1024];
  char* dst = buffer;
  dst += sprintf(dst, "    Executing \"rrdtool");
  for ( unsigned int i = 0; i < argc; i++ ){
    dst += sprintf(dst, " %s", argv[i]);
  }
  Log::verbose("status", "%s\n", buffer);

  rrd_clear_error();
  if ( rrd_update(argc, argv) < 0 ){
	  Log::fatal("status", "    rrd_update() failed: %s\n", rrd_get_error());
  }
}
#endif /* HAVE_RRDTOOL */

void MP_Status2_reset(const char* MAMPid, int noCI){
#ifdef HAVE_RRDTOOL
  char b1[1024];
  char b2[1024];

  Log::verbose("status", "Resetting RRD counters for %s\n", MAMPid);
  update(b1, b2, "-1", MAMPid, -1, -1, -1);
  update(b1, b2, "N", MAMPid, -1, 0, 0);

  for ( int i=0; i < noCI; i++ ){
      update(b1, b2, "-1", MAMPid, i, -1, -1);
      update(b1, b2, "N", MAMPid, i, 0, 0);
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
  char b1[1024];
  char b2[1024];

  update(b1, b2, "N", mampid, -1, ntohl(MPstat->packet_count), ntohl(MPstat->matched_count));

  for ( int i=0; i < MPstat->noCI; i++ ){
    update(b1, b2, "N", mampid, i, ntohl(MPstat->CI[i].packet_count), ntohl(MPstat->CI[i].matched_count));
  }
#endif /* HAVE_RRDTOOL */
}
