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
#include "database.h"

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

/* GLOBALS */
static const char* program_name;
int ma_control_port = MA_CONTROL_DEFAULT_PORT;
int ma_relay_port = MA_RELAY_DEFAULT_PORT;

char* rrdpath;
int verbose_flag = 0;
int debug_flag = 0;
FILE* verbose = NULL; /* stdout if verbose is enabled, /dev/null otherwise */

static int drop_priv_flag = 1;
static uid_t drop_uid = -1;
static gid_t drop_gid = -1;

enum LongFlags {
  FLAG_DATADIR = 256,
  FLAG_USER,
  FLAG_GROUP,
};

static struct option long_options[]= {
  {"relay",      optional_argument, 0, 'r'},
  {"iface",      required_argument, 0, 'i'},
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
    logmsg(stderr, "Not executing as uid=0, cannot drop priviledges.\n");
    return 0;
  }

  logmsg(stderr, "Dropping priviledges to uid=%d gid=%d\n", drop_uid, drop_gid);
  if ( setgid(drop_gid) != 0 ){
    logmsg(stderr, "setgid() failed: %s\n", strerror(errno));
    return 1;
  }
  if ( setuid(drop_uid) != 0 ){
    logmsg(stderr, "setuid() failed: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[]){
  printf("MArCd " VERSION " (libmarc-" LIBMARC_VERSION ")\n");
  program_name = strrchr(argv[0], '/') + 1;

  extern int opterr, optopt;
  int ret;
  
  /* defaults */
  rrdpath = strdup(DATA_DIR);
  {
    struct passwd* passwd = getpwnam("marc");
    if ( passwd ){
      drop_uid = passwd->pw_uid;
    }
  }
  {
    struct group* group = getgrnam("marc");
    if ( group ){
      drop_gid = group->gr_gid;
    }
  }

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

  /* sanity checks */
  if ( db_name[0] == 0 ){
    fprintf(stderr, "No database specified.\n");
    return 1;
  }

  /* force verbose if debug is enabled */
  verbose_flag |= debug_flag;

  /* setup vfp to stdout or /dev/null depending on verbose flag */
  verbose = stdout;
  if ( !verbose_flag ){
    verbose = fopen("/dev/null", "w");
  }

  if ( access(rrdpath, W_OK) != 0 ){
    logmsg(stderr, "Need write persmission to data dir: %s\n", rrdpath);
    return 1;
  }
  logmsg(stderr, "Datadir: %s\n", rrdpath);

  if ( (ret=ma_control_init()) != 0 ){
    logmsg(stderr, "Failed to initialize control daemon, terminating.\n");
    return ret;
  }

  if ( drop_priv_flag ){
    priviledge_drop();
  }

  ma_control_run();
  ma_control_cleanup();

  free(rrdpath);

  return 0;
}
