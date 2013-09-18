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

#include "globals.hpp"
#include "configfile.hpp"
#include "control.hpp"
#include "relay.hpp"
#include "database.hpp"
#include "log.hpp"

#include <caputils/marc.h>
#include <caputils/log.h>
#include <caputils/utils.h>
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

/* GLOBALS */
static const char* program_name;

char* rrdpath;
static int daemon_mode = 0;
static const char* pidfile = DATA_DIR"/marc.pid";
int verbose_flag = 0;
int debug_flag = 0;
static int syslog_flag = 0;
bool volatile keep_running = true;

static int drop_priv_flag = 1;
static const char* drop_username = "marc";
static const char* drop_group = "marc";
static uid_t drop_uid = 0;
static gid_t drop_gid = 0;
bool have_control_daemon = false;
bool have_relay_daemon = false;

enum LongFlags {
	FLAG_DATADIR = 256,
	FLAG_USER,
	FLAG_GROUP,
	FLAG_SYSLOG,
	FLAG_PIDFILE,
	FLAG_DAEMON
};

static const char* shortopts = "r::i:l:sbH:N:u:p:f:vqdh";
static struct option longopts[] = {
	{"relay",      optional_argument, 0, 'r'},
	{"iface",      required_argument, 0, 'i'},
	{"listen",     required_argument, 0, 'l'},
	{"datadir",    required_argument, 0, FLAG_DATADIR},
	{"syslog",     no_argument,       0, 's'},
	{"daemon",     no_argument,       0, 'b'},
	{"pidfile",    required_argument, 0, FLAG_PIDFILE},

	/* database options */
	{"dbhost",     required_argument, 0, 'H'},
	{"database",   required_argument, 0, 'N'},
	{"dbusername", required_argument, 0, 'u'},
	{"dbpassword", required_argument, 0, 'p'},

	/* privilege dropping */
	{"drop",       no_argument, &drop_priv_flag, 1},
	{"no-drop",    no_argument, &drop_priv_flag, 0},
	{"user",       required_argument, 0, FLAG_USER},
	{"group",      required_argument, 0, FLAG_GROUP},

	/* other */
	{"config",    required_argument, 0, 'f'},
	{"verbose",   no_argument,       0, 'v'},
	{"quiet",     no_argument,       0, 'q'},
	{"debug",     no_argument,       0, 'd'},
	{"help",      no_argument,       0, 'h'},

	/* sentinel */
	{0, 0, 0, 0}
};

void show_usage(){
	printf("(C) 2004 patrik.arlos@bth.se\n");
	printf("(C) 2013 david.sveningsson@bth.se\n");
	printf("Usage: %s [OPTIONS] DATABASE\n", program_name);
	printf("  -r, --relay[=PORT]  In addition to running MArCd, setup relaying so a\n"
	       "                      separate MArelayD isn't needed.\n"
	       "  -i, --iface=IFACE   Only listen on IFACE (relay only).\n"
	       "  -l, --listen=IP     Only listen on IP [default: 0.0.0.0].\n"
	       "      --datadir=PATH  Use PATH as rrdtool data storage. [default: \n"
	       "                      " DATA_DIR "]\n"
	       "  -s, --syslog        Write output to syslog instead of stderr.\n"
	       "  -b, --daemon        Fork to background.\n"
	       "      --pidfile=FILE  When in daemon mode it stores the pid here\n"
#ifdef HAVE_INIPARSER_H
	       "  -f, --config=PATH   Load configuration from PATH [default: " MARCD_DEFAULT_CONFIG_FILE "]\n"
#endif
	       "\n"
	       "Database options\n"
	       "  -H, --dbhost        MySQL database host. [Default: localhost]\n"
	       "  -N, --database      Database name.\n"
	       "  -u, --dbusername    Database username. [Default: current user]\n"
	       "  -p, --dbpassword    Database password, use '-' to read password from\n"
	       "                      stdin. [Default: none]\n"
	       "\n"
	       "Privilege options\n"
	       "      --drop          Drop privileges. [default]\n"
	       "      --no-drop       Inverse of --drop.\n"
	       "      --user USER     Change UID to this user. [default: marc]\n"
	       "      --group GROUP   Change GID to this group. [default: marc]\n"
	       "\n"
	       "Other\n"
	       "  -v, --verbose       Verbose output.\n"
	       "  -q, --quiet         Inverse of --verbose.\n"
	       "  -d, --debug         Show extra debugging output, including hexdump of\n"
	       "                      all incomming and outgoing messages. Implies\n"
	       "                      verbose output.\n"
	       "  -h, --help          This text\n");
}

static int privilege_drop(){
	Log::message(MAIN, "Dropping privileges to %s(%d):%s(%d)\n", drop_username, drop_uid, drop_group, drop_gid);
	if ( setgid(drop_gid) != 0 ){
		Log::error(MAIN, "  setgid() failed: %s\n", strerror(errno));
		return 1;
	}
	if ( setuid(drop_uid) != 0 ){
		Log::error(MAIN, "  setuid() failed: %s\n", strerror(errno));
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
	Log::message(MAIN, "%s-"VERSION" (caputils-%s) starting.\n", program_name, caputils_version(NULL));
}

static const char* get_username(const uid_t id){
	static char buf[128];
	struct passwd* passwd = getpwuid(id);
	if ( !passwd ){
		return NULL;
	}
	strncpy(buf, passwd->pw_name, sizeof(buf));
	return buf;
}

static const char* get_groupname(const gid_t id){
	static char buf[128];
	struct group* group = getgrgid(id);
	if ( !group ){
		return NULL;
	}
	strncpy(buf, group->gr_name, sizeof(buf));
	return buf;
}

static void default_env(){
	rrdpath = strdup(DATA_DIR);

	struct passwd* passwd = getpwnam(drop_username);
	struct group* group = getgrnam(drop_group);
	if ( passwd ){
		drop_uid = passwd->pw_uid;
	} else {
		fprintf(stderr, "%s: no such user `%s': defaulting to current user\n", program_name, drop_username);
		drop_uid = getuid();
		drop_username = get_username(drop_uid);
	}
	if ( group ){
		drop_gid = group->gr_gid;
	} else {
		fprintf(stderr, "%s: no such group `%s': defaulting to current primary group\n", program_name, drop_group);
		drop_gid = getgid();
		drop_group = get_groupname(drop_gid);
	}

	/* set database username to current user */
	struct passwd* user = getpwuid(getuid());
	if ( user ){
		strncpy(db_username, user->pw_name, sizeof(db_username));
		db_username[sizeof(db_username)-1] = '\0';
	} else {
		fprintf(stderr, "%s: failed to get current user\n", program_name);
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

	if ( daemon_mode && access(pidfile, R_OK) == 0 ){
		Log::fatal(MAIN, "pidfile `%s' already exists, make sure no other %s is running.\n", pidfile, program_name);
		return 0;
	}

	return 1;
}

static void show_env(){
	Log::message(MAIN, "Environment:\n");
	Log::message(MAIN, "  Datadir: %s\n", rrdpath);
	Log::message(MAIN, "  Pidfile: %s\n", pidfile);
	if ( drop_priv_flag ){
		Log::message(MAIN, "  User/Group: %s(%d):%s(%d)\n", drop_username, drop_uid, drop_group, drop_gid);
	}
	Log::message(MAIN, "  Database: mysql://%s@%s/%s\n", db_username, db_hostname, db_name);
}

static void handle_signal(int signum){
	putc('\r', stderr);
	if ( keep_running ){
		Log::message(MAIN, "Caught signal %d, stopping threads.\n", signum);
		keep_running = false;
		Daemon::interupt_all();
	} else {
		Log::fatal(MAIN, "Caught signal again, aborting.\n");
		abort();
	}
}

static void set_username(const char* username){
	const struct passwd* passwd = getpwnam(username);
	if ( !passwd ){
		Log::fatal(MAIN, "No such user `%s', aborting.\n", username);
		abort();
	}
	drop_uid = passwd->pw_uid;
	drop_username = username;
}

static void set_group(const char* groupname){
	const struct group* group = getgrnam(groupname);
	if ( !group ){
		Log::fatal(MAIN, "No such group `%s', aborting.\n", groupname);
		abort();
	}
	drop_gid = group->gr_gid;
	drop_group = groupname;
}

static void set_relay_iface(const char* iface){
	if ( (relay.iface=if_nametoindex(iface)) == 0 ){
		fprintf(stderr, "%s: `%s' is not a valid interface.\n", program_name, iface);
		exit(1);
	}
}

static void set_control_ip(const char* addr){
	if ( inet_aton(addr, &control.addr) == 0 ){
		Log::fatal(MAIN, "`%s' is not a valid IPv4 address\n", addr);
		exit(1);
	}
}

#ifdef HAVE_INIPARSER_H
#endif /* HAVE_INIPARSER_H */

int main(int argc, char *argv[]){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	default_env();

	int ret;
	int option_index = 0;
	int op;

#ifdef HAVE_INIPARSER_H
	if ( config::load(argc, argv) != 0 ){ /* passing argv so it can read -f/--config */
		return 1; /* error already shown */
	}
#endif

	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case '?': /* error */
			exit(1);

		case 0: /* long opt */
			break;

		case 'b': /* --daemon */
			daemon_mode = 1;
			break;

		case 's': /* --syslog */
			syslog_flag = 1;
			break;

		case FLAG_USER: /* --user */
			set_username(optarg);
			break;

		case FLAG_GROUP: /* --group */
			set_group(optarg);
			break;

		case 'f':
#ifndef HAVE_INIPARSER_H
			fprintf(stderr, "%s: configuration files not supported (build with --with-iniparser)\n", program_name);
#endif
			break;

		case 'H':
			strncpy(db_hostname, optarg, sizeof(db_hostname));
			db_hostname[sizeof(db_hostname)-1] = '\0';
			break;

		case 'N':
			strncpy(db_name, optarg, sizeof(db_name));
			db_name[sizeof(db_name)-1] = '\0';
			break;

		case 'u':
			strncpy(db_username, optarg, sizeof(db_username));
			db_username[sizeof(db_username)-1] = '\0';
			break;

		case 'p':
			if ( strcmp(optarg, "-") == 0 ){ /* read password from stdin */
				strncpy(db_password, getpass("mysql password: "), sizeof(db_password));
			} else {
				strncpy(db_password, optarg, sizeof(db_password));
			}
			db_password[sizeof(db_password)-1] = '\0';
			break;

		case 'i': /* --iface */
			set_relay_iface(optarg);
			break;

		case 'l': /* --listen */
			set_control_ip(optarg);
			break;

		case 'r': /* --relay */
			have_relay_daemon = true;

			if ( optarg ){
				int tmp = atoi(optarg);
				if ( tmp > 0 ){
					relay.port = tmp;
				} else {
					Log::error(MAIN, "Invalid port given to --relay: %s. Ignored\n", optarg);
				}
			}

			break;

		case FLAG_DATADIR:
			free(rrdpath);
			rrdpath = strdup(optarg);
			break;

		case FLAG_PIDFILE:
			pidfile = optarg;
			break;

		case 'v': /* --verbose */
			verbose_flag = 1;
			break;

		case 'q': /* --quiet */
			verbose_flag = 0;
			break;

		case 'd': /* --debug */
			debug_flag = 1;
			break;

		case 'h': /* --help */
			show_usage();
			exit(0);

		default:
			if ( option_index >= 0 ){
				fprintf(stderr, "flag --%s declared but not handled\n", longopts[option_index].name);
			} else {
				fprintf(stderr, "flag -%c declared but not handled\n", op);
			}
			abort();
		}
	}

	/* database */
	if ( argc > optind ){
		strncpy(db_name, argv[optind], sizeof(db_name));
		db_name[sizeof(db_name)-1] = '\0';
	}

	setup_output();

	/* test if possible to drop privileges */
	if ( drop_priv_flag && getuid() != 0 ){
		Log::message(MAIN, "Not executing as uid=0, cannot drop privileges.\n");
		drop_priv_flag = 0;
	}

	/* Drop privileges.
	 * Done before forking since unlinking requires write permission to folder so
	 * if it fails to write it will fail unlinking. It is also done before
	 * check_env so it actually check environment for the dropped user instead of
	 * root.
	 */
	if ( drop_priv_flag ){
		privilege_drop();
	}

	/* sanity checks */
	show_env();
	if ( !check_env() ){
		return 1;
	}

	if ( daemon_mode ){
		/* opening file before fork since it will be a fatal error if it fails to write the pid */
		FILE* fp = fopen(pidfile, "w");
		if ( !fp ){
			Log::fatal(MAIN, "failed to open '%s` for writing: %s\n", pidfile, strerror(errno));
			return 1;
		}

		Log::message(MAIN, "Forking to background\n");
		pid_t pid = fork();

		if ( pid ){ /* parent */
			fprintf(fp, "%d\n", pid);
			fclose(fp);

			/* change owner of pidfile */
			if ( drop_priv_flag ){
				chown(pidfile, drop_uid, drop_gid);
			}

			return 0;
		}

		fclose(fp);
	}

	/* initialize daemons */
	pthread_barrier_t barrier;
	int threads = 1;
	threads += (int)have_control_daemon;
	threads += (int)have_relay_daemon;
	pthread_barrier_init(&barrier, NULL, threads);
	control.addr = relay.addr;

	if ( have_control_daemon && (ret=Daemon::instantiate<Control>(2000, &barrier)) != 0 ){
		Log::fatal(MAIN, "Failed to initialize control daemon, terminating.\n");
		if ( daemon_mode && unlink(pidfile) == -1 ){
			Log::fatal(MAIN, "Failed to remove pidfile: %s\n", strerror(errno));
		}
		return ret;
	}

	if ( have_relay_daemon && (ret=Daemon::instantiate<Relay>(2000, &barrier)) != 0 ){
		Log::fatal(MAIN, "Failed to initialize relay daemon, terminating.\n");
		if ( daemon_mode && unlink(pidfile) == -1 ){
			Log::fatal(MAIN, "Failed to remove pidfile: %s\n", strerror(errno));
		}
		return ret;
	}

	/* install signal handler */
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	/* release all threads and wait for them to finish*/
	pthread_barrier_wait(&barrier);
	if ( daemon_mode ){
		Log::message(MAIN, "Threads started. Going to sleep.\n");
	} else {
		Log::message(MAIN, "Threads started. Going to sleep. Abort with SIGINT\n");
	}
	Daemon::join_all();

	/* cleanup */
	free(rrdpath);
	if ( daemon_mode && unlink(pidfile) == -1 ){
		Log::fatal(MAIN, "Failed to remove pidfile: %s\n", strerror(errno));
	}

	Log::message(MAIN, "%s terminated.\n", program_name);
	return 0;
}
