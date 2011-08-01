/***************************************************************************
                          MARcD.cpp  -  description
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

#include <libmarc/libmarc.h>
#include <libmarc/version.h>
#include <libmarc/log.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <errno.h>

#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/ioctl.h>

/* GLOBALS */
static const char* program_name;
int ma_control_port = MA_CONTROL_DEFAULT_PORT;
int ma_relay_port = MA_RELAY_DEFAULT_PORT;

char* rrdpath;
char* iface = NULL;
in_addr listen_addr = { htonl(INADDR_ANY) };
int verbose_flag = 0;
int debug_flag = 0;
FILE* verbose = NULL; /* stdout if verbose is enabled, /dev/null otherwise */
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
};

static struct option long_options[]= {
  {"relay",      optional_argument, 0, 'r'},
  {"iface",      required_argument, 0, 'i'},
  {"listen",     required_argument, 0, 'm'},
  {"datadir",    required_argument, 0, FLAG_DATADIR},

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
	 "      --verbose       Verbose output.\n"
	 "      --quiet         Inverse of --verbose.\n"
	 "      --debug         Show extra debugging output, including hexdump of\n"
	 "                      all incomming and outgoing messages. Implies\n"
	 "                      verbose output.\n"
	 "      --help          This text\n");
}

static int priviledge_drop(){
  if ( getuid() != 0 ){
    logmsg(stderr, "[  main ] Not executing as uid=0, cannot drop priviledges.\n");
    return 0;
  }

  logmsg(stderr, "[  main ] Dropping priviledges to uid=%d gid=%d\n", drop_uid, drop_gid);
  if ( setgid(drop_gid) != 0 ){
    logmsg(stderr, "[  main ] setgid() failed: %s\n", strerror(errno));
    return 1;
  }
  if ( setuid(drop_uid) != 0 ){
    logmsg(stderr, "[  main ] setuid() failed: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

static void setup_output(){
  /* force verbose if debug is enabled */
  verbose_flag |= debug_flag;
  
  /* setup vfp to stdout or /dev/null depending on verbose flag */
  verbose = verbose_flag ? stdout : fopen("/dev/null", "w");
  
  /* redirect output */
  marc_set_output_handler(logmsg, vlogmsg, stderr, verbose);
}

static void default_env(){
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
    fprintf(stderr, "[  main ] No database specified.\n");
    return 0;
  }
  
  if ( access(rrdpath, W_OK) != 0 ){
    logmsg(stderr, "[  main ] Need write persmission to data dir: %s\n", rrdpath);
    return 0;
  }
  return 1;
}

static void show_env(){
  logmsg(stderr, "[  main ] Datadir: %s\n", rrdpath);
}

static void sigint(int signum){
  putc('\r', stderr);
  if ( keep_running ){
    logmsg(stderr, "[  main ] Caught termination signal, stopping threads.\n");
    keep_running = false;
    Daemon::interupt_all();
  } else {
    logmsg(stderr, "[  main ] Caught termination signal again, aborting.\n");
    exit(1);
  }
}

int main(int argc, char *argv[]){
  printf("MArCd " VERSION " (libmarc-" LIBMARC_VERSION ")\n");
  program_name = strrchr(argv[0], '/') + 1;

  default_env();

  extern int opterr, optopt;
  int ret;
  int option_index = 0;
  int op;

  opterr=0;
  optopt=0;
  while ( (op = getopt_long(argc, argv, "r::i:h:u:p:", long_options, &option_index)) != -1 ){
    switch (op){
    case 0: /* long opt */
      break;

    case 'v':
      show_usage();
      exit(0);
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
	  logmsg(stderr, "Failed to open socket: %s\n", strerror(errno));
	  exit(1);
	}

	if( ioctl(sd, SIOCGIFINDEX, &ifr) == -1 ) {
	  logmsg(stderr, "%s is not a valid interface: %s", optarg, strerror(errno));
	  continue;
	}

	if( ioctl(sd, SIOCGIFADDR, &ifr) == -1 ) {
	  logmsg(stderr, "Failed to get IP on interface %s: %s", optarg, strerror(errno));
	  continue;
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
	  logmsg(stderr, "Invalid port given to --relay: %s. Ignored\n", optarg);
	}
      }

      break;

    case FLAG_DATADIR:
      free(rrdpath);
      rrdpath = strdup(optarg);
      break;

    default:
      fprintf(stderr, "?? getopt returned character code 0%o ??\n", op);
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

  /* install signal handler */
  signal(SIGINT, sigint);

  /* initialize daemons */
  pthread_barrier_t barrier;
  int threads = 1;
  threads += (int)have_control_daemon;
  threads += (int)have_relay_daemon;
  pthread_barrier_init(&barrier, NULL, threads);

  if ( have_control_daemon && (ret=Daemon::instantiate<Control>(200, &barrier)) != 0 ){
    logmsg(stderr, "Failed to initialize control daemon, terminating.\n");
    return ret;
  }

  if ( have_relay_daemon && (ret=Daemon::instantiate<Relay>(200, &barrier)) != 0 ){
    logmsg(stderr, "Failed to initialize relay daemon, terminating.\n");
    return ret;
  }

  /* drop priviledges */
  if ( drop_priv_flag ){
    priviledge_drop();
  }

  /* release all threads and wait for them to finish*/
  pthread_barrier_wait(&barrier);
  Daemon::join_all();

  /* cleanup */
  free(rrdpath);

  return 0;
}
