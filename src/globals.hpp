#ifndef GLOBALS_H
#define GLOBALS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

struct listen {
	int port;
	in_addr addr;
	int iface;
};

extern struct listen control;
extern struct listen relay;

/* configuration */
extern int verbose_flag;                    /* if true user want verbose output */
extern int debug_flag;                      /* if true user want debug output */
extern bool syslog_flag;                    /* if true output should go to syslog */
extern char* rrdpath;                       /* path to store rrdtools data in */
extern const char* pidfile;                 /* which file hold the pid */
extern bool have_control_daemon;            /* if true daemon should run */
extern bool have_relay_daemon;              /* if true relay should run */
extern bool drop_priv_flag;                 /* if true privileges should be dropped */
extern const char* drop_username;
extern const char* drop_group;
extern uid_t drop_uid;
extern gid_t drop_gid;

#endif /* GLOBALS_H */
