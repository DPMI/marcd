/***************************************************************************
                          MArCd.cpp  -  description
                             -------------------
    begin                : Mon 28 Nov, 2005
    copyright            : (C) 2005 by Patrik Arlos
                         : (C) 2011 by David Sveningsson
    email                : patrik.arlos@bth.se
                         : david.sveningsson@bth.se
***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "control.h"
#include "relay.h"
#include "database.h"
#include "log.h"

#include <caputils/marc.h>
#include <caputils/log.h>
#include <caputils/version.h>
#define MAIN "main"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <getopt.h>
#include <errno.h>

#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/ioctl.h>

#ifdef HAVE_INIPARSER_H
#include <iniparser.h>
#define MARCD_DEFAULT_CONFIG_FILE "marcd.conf"
#endif

/* GLOBALS */
static const char* program_name;
int ma_control_port = MA_CONTROL_DEFAULT_PORT;
int ma_relay_port = MA_RELAY_DEFAULT_PORT;

char* rrdpath;
char* iface = NULL;
in_addr listen_addr;
in_addr control_addr;
int verbose_flag = 0;
int debug_flag = 0;
static int syslog_flag = 0;
bool volatile keep_running = true;

static int drop_priv_flag = 1;
static uid_t drop_uid = -1;
static gid_t drop_gid = -1;
static bool have_control_daemon = false;
static bool have_relay_daemon = false;

enum LongFlags {
	FLAG_DATADIR = 256,
	FLAG_USER,
	FLAG_GROUP,
	FLAG_SYSLOG,
};

static struct option long_options[]= {
	{"relay",      optional_argument, 0, 'r'},
	{"iface",      required_argument, 0, 'i'},
	{"listen",     required_argument, 0, 'm'},
	{"datadir",    required_argument, 0, FLAG_DATADIR},
	{"syslog",     no_argument,       &syslog_flag, 1},

	/* database options */
	{"dbhost",     required_argument, 0, 'h'},
	{"database",   required_argument, 0, 'd'},
	{"dbusername", required_argument, 0, 'u'},
	{"dbpassword", required_argument, 0, 'p'},

	/* priviledge dropping */
	{"drop",       no_argument, &drop_priv_flag, 1},
	{"no-drop",    no_argument, &drop_priv_flag, 0},
	{"user",       required_argument, 0, FLAG_USER},
	{"group",      required_argument, 0, FLAG_GROUP},

	/* other */
	{"config",    required_argument, 0, 'f'},
	{"verbose",   no_argument, &verbose_flag, 1},
	{"quiet",     no_argument, &verbose_flag, 0},
	{"debug",     no_argument, &debug_flag, 1},
	{"help",      no_argument, 0, 'v'},

	/* sentinel */
	{0, 0, 0, 0}
};

void show_usage(){
	printf("(C) 2004 patrik.arlos@bth.se\n");
	printf("(C) 2011 david.sveningsson@bth.se\n");
	printf("Usage: %s [OPTIONS] DATABASE\n", program_name);
	printf("  -r, --relay[=PORT]  In addition to running MArCd, setup relaying so a\n"
	       "                      separate MArelayD isn't needed.\n"
	       "  -i, --iface=IFACE   Only listen on IFACE.\n"
	       "  -m, --listen=IP     Only listen on IP.\n"
	       "      --datadir=PATH  Use PATH as rrdtool data storage. [default: \n"
	       "                      " DATA_DIR "]\n"
	       "      --syslog        Write output to syslog instead of stderr.\n"
	       "\n"
	       "Database options\n"
	       "  -h, --dbhost        MySQL database host. [Default: localhost]\n"
	       "      --database      Database name.\n"
	       "  -u, --dbusername    Database username. [Default: current user]\n"
	       "  -p, --dbpassword    Database password, use '-' to read password from\n"
	       "                      stdin. [Default: none]\n"
	       "\n"
	       "Priviledge options\n"
	       "      --drop          Drop priviledges. [default]\n"
	       "      --no-drop       Inverse of --drop.\n"
	       "      --user USER     Change UID to this user. [default: marc]\n"
	       "      --group GROUP   Change GID to this group. [default: marc]\n"
	       "\n"
	       "Other\n"
#ifdef HAVE_INIPARSER_H
	       "  -f, --config=PATH   Load configuration from PATH [default: " MARCD_DEFAULT_CONFIG_FILE "]\n"
#endif
	       "      --verbose       Verbose output.\n"
	       "      --quiet         Inverse of --verbose.\n"
	       "      --debug         Show extra debugging output, including hexdump of\n"
	       "                      all incomming and outgoing messages. Implies\n"
	       "                      verbose output.\n"
	       "      --help          This text\n");
}

static int priviledge_drop(){
	if ( getuid() != 0 ){
		Log::message(MAIN, "Not executing as uid=0, cannot drop priviledges.\n");
		return 0;
	}

	Log::message(MAIN, "Dropping priviledges to uid=%d gid=%d\n", drop_uid, drop_gid);
	if ( setgid(drop_gid) != 0 ){
		Log::error(MAIN, "setgid() failed: %s\n", strerror(errno));
		return 1;
	}
	if ( setuid(drop_uid) != 0 ){
		Log::error(MAIN, "setuid() failed: %s\n", strerror(errno));
		return 1;
	}

	return 0;
}

int vlogmsg_wrapper(FILE* fd, const char* fmt, va_list ap){
	/* this "casting" is needed to workaround precision errors because pointers
	 * isn't supposed to be abused like this */
	Log::Severity s = Log::NORMAL;
	if ( fd == (FILE*)Log::VERBOSE ) s = Log::VERBOSE;

	Log::log("MArCd", s, fmt, ap);
	return 1;
}

int logmsg_wrapper(FILE* fd, const char* fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = vlogmsg_wrapper(fd, fmt, ap);
	va_end(ap);
	return ret;
}

static void setup_output(){
	/* force verbose if debug is enabled */
	verbose_flag |= debug_flag;

	/* redirect output (Ugly pointer casting but the "pointers" is never
	 * dereferenced but passed directly to {,v}logmsg_wrapper which uses it as
	 * severity. */
	marc_set_output_handler(logmsg_wrapper, vlogmsg_wrapper, (FILE*)Log::NORMAL, (FILE*)Log::VERBOSE);

	/* initialize log */
	Log::Severity severity = Log::NORMAL;
	if ( debug_flag ) severity = Log::DEBUG;
	else if ( verbose_flag ) severity = Log::VERBOSE;

	if ( syslog_flag == 0 ){
		Log::set_file_destination(stderr, severity);
	} else {
		Log::set_syslog_destination(severity);
	}
	Log::message(MAIN, "%s-"VERSION" starting.", program_name);
}

static void default_env(){
	listen_addr.s_addr = htonl(INADDR_ANY);
	rrdpath = strdup(DATA_DIR);
	struct passwd* passwd = getpwnam("marc");
	struct group* group = getgrnam("marc");
	if ( passwd ){
		drop_uid = passwd->pw_uid;
	}
	if ( group ){
		drop_gid = group->gr_gid;
	}
	if ( strcmp(program_name, "MArelayD") == 0 ){
		have_relay_daemon = true;
	} else {
		have_control_daemon = true;
	}
}

static int check_env(){
	if ( db_name[0] == 0 ){
		Log::fatal(MAIN, "No database specified.\n");
		return 0;
	}

	if ( db_username[0] == 0 ){
		Log::fatal(MAIN, "No database user specified.\n");
		return 0;
	}

	if ( access(rrdpath, W_OK) != 0 ){
		Log::fatal(MAIN, "Need write persmission to data dir: %s\n", rrdpath);
		return 0;
	}
	return 1;
}

static void show_env(){
	Log::message(MAIN, "Datadir: %s\n", rrdpath);
}

static void sigint(int signum){
	putc('\r', stderr);
	if ( keep_running ){
		Log::message(MAIN, "Caught termination signal, stopping threads.\n");
		keep_running = false;
		Daemon::interupt_all();
	} else {
		Log::fatal(MAIN, "Caught termination signal again, aborting.\n");
		abort();
	}
}

#ifdef HAVE_INIPARSER_H
int load_config(int argc, char* argv[]){
	const char* filename = NULL;
	dictionary* config = NULL;

	/* locate configuration filename. This is done before getopt since getopt has
	 * precedence over conf, so if this is run after getopt it would overwrite
	 * getopt instead of vice-versa. */
	for ( int i = 0; i < argc; i++ ){
		int a = strcmp(argv[i], "-f") == 0;
		int b = strcmp(argv[i], "--config") == 0;
		if ( !(a||b) ){
			continue;
		}

		if ( i+1 == argc ){
			fprintf(stderr, "%s: missing argument to %s.\n", program_name, argv[i]);
			return 1;
		}

		filename = argv[i+1];
	}

	/* if no configuration file was explicitly required try default paths */
	if ( !filename ){
		/* try in sysconfdir ($prefix/etc by default) */
		char* tmp;
		int ret = asprintf(&tmp, "%s/%s", SYSCONF_DIR, MARCD_DEFAULT_CONFIG_FILE);
		if ( ret == -1 ){
			fprintf(stderr, "%s: %s\n", program_name, strerror(errno));
			exit(1);
		}

		if ( access(tmp, R_OK) == 0 ){
			char* mem = (char*)alloca(strlen(tmp)+1); /* allocate on stack */
			strcpy(mem, tmp);
			free(tmp);
			filename = mem;
		}

		/* try default filename in pwd (has precedence of sysconfdir) */
		if ( access(MARCD_DEFAULT_CONFIG_FILE, R_OK) == 0 ){
			filename = MARCD_DEFAULT_CONFIG_FILE;
		}
	}

	/* if we still don't have a filename we ignore it, the user hasn't requested
	 * anything and no default could be located. */
	if ( !filename ){
		return 0;
	}

	Log::message(MAIN, "Loading configuration from \"%s\".\n", filename);

	/* parse configuration */
	if ( !(config=iniparser_load(filename)) ){
		return 1;
	}

	const char* value = NULL;

	/* mysql hostname */
	if ( (value=iniparser_getstring(config, "mysql:hostname", NULL)) ){
		strncpy(db_hostname, value, sizeof(db_hostname));
		db_hostname[sizeof(db_hostname)-1] = '\0';
	}

	/* mysql username */
	if ( (value=iniparser_getstring(config, "mysql:username", NULL)) ){
		strncpy(db_username, value, sizeof(db_username));
		db_username[sizeof(db_username)-1] = '\0';
	}

	/* mysql password */
	if ( (value=iniparser_getstring(config, "mysql:password", NULL)) ){
		strncpy(db_password, value, sizeof(db_password));
		db_password[sizeof(db_password)-1] = '\0';
	}

	/* mysql database */
	if ( (value=iniparser_getstring(config, "mysql:database", NULL)) ){
		strncpy(db_name, value, sizeof(db_name));
		db_name[sizeof(db_name)-1] = '\0';
	}

	/* relay */
	have_relay_daemon = iniparser_getboolean(config, "general:relay", 0);

	return 0;
}
#endif /* HAVE_INIPARSER_H */

int main(int argc, char *argv[]){
	printf("MArCd " VERSION " (caputils-" CAPUTILS_VERSION ")\n");

	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	default_env();

	extern int opterr, optopt;
	int ret;
	int option_index = 0;
	int op;

#ifdef HAVE_INIPARSER_H
	if ( load_config(argc, argv) != 0 ){ /* passing argv so it can read -f/--config */
		return 1; /* error already shown */
	}
#endif

	opterr=0;
	optopt=0;
	while ( (op = getopt_long(argc, argv, "r::i:h:u:p:f:", long_options, &option_index)) != -1 ){
		switch (op){
		case 0: /* long opt */
			break;

		case 'v':
			show_usage();
			exit(0);
			break;

		case 'f':
#ifndef HAVE_INIPARSER_H
			fprintf(stderr, "%s: configuration files not supported (build with --with-iniparser)\n", program_name);
#endif
			break;

		case 'h':
			strncpy(db_hostname, optarg, sizeof(db_hostname));
			db_hostname[sizeof(db_hostname)-1] = '\0';
			break;

		case 'd':
			strncpy(db_name, optarg, sizeof(db_name));
			db_name[sizeof(db_name)-1] = '\0';
			break;

		case 'u':
			strncpy(db_username, optarg, sizeof(db_username));
			db_username[sizeof(db_username)-1] = '\0';
			break;

		case 'p':
			if ( strcmp(optarg, "-") == 0 ){ /* read password from stdin */
				if ( fscanf(stdin, "%63s", db_password) != 1 ){
					fprintf(stderr, "Failed to read password.\n");
					return 1;
				}
			} else {
				strncpy(db_password, optarg, sizeof(db_password));
				db_password[sizeof(db_password)-1] = '\0';
			}
			break;

		case 'i': /* --iface */
		{
			/* check if iface exists */
			struct ifreq ifr;
			strncpy(ifr.ifr_name, optarg, IFNAMSIZ);
			int sd = socket(AF_INET, SOCK_DGRAM, 0);

			if ( sd < 0 ){
				Log::fatal(MAIN, "Failed to open socket: %s\n", strerror(errno));
				exit(1);
			}

			if( ioctl(sd, SIOCGIFINDEX, &ifr) == -1 ) {
				Log::fatal(MAIN, "%s is not a valid interface: %s", optarg, strerror(errno));
				exit(1);
			}

			if( ioctl(sd, SIOCGIFADDR, &ifr) == -1 ) {
				Log::fatal(MAIN, "Failed to get IP on interface %s: %s", optarg, strerror(errno));
				exit(1);
			}

			iface = optarg;
			listen_addr = ((sockaddr_in*)&ifr.ifr_addr)->sin_addr;
		}
		break;

		case 'r': /* --relay */
			have_relay_daemon = true;

			if ( optarg ){
				int tmp = atoi(optarg);
				if ( tmp > 0 ){
					ma_relay_port = tmp;
				} else {
					Log::error(MAIN, "Invalid port given to --relay: %s. Ignored\n", optarg);
				}
			}

			break;

		case FLAG_DATADIR:
			free(rrdpath);
			rrdpath = strdup(optarg);
			break;

		default:
			fprintf(stderr, "unhandled option '%c'.\n", op);
			abort();
		}
	}

	/* database */
	if ( argc > optind ){
		strncpy(db_name, argv[optind], sizeof(db_name));
		db_name[sizeof(db_name)-1] = '\0';
	}

	setup_output();

	/* sanity checks */
	if ( !check_env() ){
		return 1;
	}
	show_env();

	/* initialize daemons */
	pthread_barrier_t barrier;
	int threads = 1;
	threads += (int)have_control_daemon;
	threads += (int)have_relay_daemon;
	pthread_barrier_init(&barrier, NULL, threads);
	control_addr.s_addr = listen_addr.s_addr;

	if ( have_control_daemon && (ret=Daemon::instantiate<Control>(2000, &barrier)) != 0 ){
		Log::fatal(MAIN, "Failed to initialize control daemon, terminating.\n");
		return ret;
	}

	if ( have_relay_daemon && (ret=Daemon::instantiate<Relay>(2000, &barrier)) != 0 ){
		Log::fatal(MAIN, "Failed to initialize relay daemon, terminating.\n");
		return ret;
	}

	/* drop priviledges */
	if ( drop_priv_flag ){
		priviledge_drop();
	}

	/* install signal handler */
	signal(SIGINT, sigint);

	/* release all threads and wait for them to finish*/
	pthread_barrier_wait(&barrier);
	Log::message(MAIN, "Threads started. Going to sleep. Abort with SIGINT\n");
	Daemon::join_all();

	/* cleanup */
	free(rrdpath);

	Log::message(MAIN, "%s terminated.\n", program_name);
	return 0;
}
