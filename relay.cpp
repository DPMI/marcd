/***************************************************************************
                          udpserver.cpp  -  description
                             -------------------
    begin                : Wed Oct 30 2002
    copyright            : (C) 2002 by Anders Ekberg
                         : (C) 2011 by David Sveningsson
    email                : anders.ekberg@bth.se
                         : david.sveningsson@{bth.se,sidvind.com}
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
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <ctime>
#include <sys/time.h>
#include <csignal>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close() */
#include <string.h> /* memset() */
#include <stdlib.h>
#include <iostream>

#include <getopt.h>

#include "relay.h"
#include "log.h"

#ifndef BUILD_RELAY
#include "database.h"
#else
/* if we're building the relay (and maybe only the relay) we don't want to
 * depend on the mysql libraries, so the database header isn't included at all
 * and there replacement variables is declared directly. */
char db_hostname[64] = "localhost";
int  db_port = 3306;
char db_name[64] = {0,};
char db_username[64] = {0,};
char db_password[64] = {0,};
#endif

#include <caputils/log.h>

#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <cassert>

#define MAX_MSG 1500

extern int debug_flag;
extern const char* iface;
extern int ma_control_port;
extern int ma_relay_port;
extern in_addr listen_addr;
extern in_addr control_addr;
extern bool volatile keep_running;

struct MAINFO {
	uint32_t version;
	char address[16];
	uint32_t port;
	char database[64];
	char user[64];
	char password[64];
	uint32_t portUDP;
} __attribute__((packed));

Relay::Relay()
	: sd(0) {

}

int Relay::init(){
	/* socket creation */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if ( sd < 0 ) {
		Log::fatal("relay", "cannot open socket (%d): %s\n", errno, strerror(errno));
		return 1;
	}

	int on = 1;
	setsockopt(sd,SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
	setsockopt(sd,SOL_SOCKET, SO_BROADCAST, &on, sizeof(int));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* bind local server port */
	addr.sin_port = htons(ma_relay_port);
	Log::fatal("relay", "Listens to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	if ( bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ){
		Log::fatal("relay", "cannot bind port number %d\n", ma_relay_port);
		return 1;
	}

	Log::verbose("relay", "Relay info:\n");
	Log::verbose("relay", "  MArC: %s:%d\n", inet_ntoa(control_addr), ma_control_port);
	if ( db_name[0] == 0 ){
		Log::verbose("relay", "  Database: unset\n");
	} else {
		Log::verbose("relay", "  Database: mysql://%s%s%s:%d/%s (using password: %s)\n",
		             db_username, db_username[0] ? "@" : "", db_hostname, db_port, db_name, db_password[0] != 0 ? "YES" : "NO");
	}

	return 0;
}

int Relay::cleanup(){
	Log::fatal("relay", "Thread finished.\n");
	return 0;
}

int Relay::run(){
	int counter = 0;
	MAINFO msg, self;
	struct sockaddr_in from;

	memset(&self, 0, sizeof(MAINFO));
	self.version = 2;
	strncpy(self.address, inet_ntoa(control_addr), 16);
	strncpy(self.database, db_name, 64);
	strncpy(self.user, db_username, 64);
	strncpy(self.password, db_password, 64);
	self.port = db_port;
	self.portUDP = ma_control_port;

	/* file descriptors to watch */
	struct pollfd fds[2] = {
		{sd, POLLIN, 0},
		{interupt_fd(), POLLIN, 0}
	};

	int timeout = 10000; /* ms */

	while ( keep_running ){
		/* wait for anything to arrive */
		poll(fds, 2, timeout);
		if ( !(fds[0].revents & POLLIN) ) continue; /* no data */
		if (   fds[1].revents & POLLIN  ) continue; /* interupted */

		/* reset buffer */
		memset(&msg, 0, sizeof(MAINFO));

		/* receive message */
		socklen_t addrlen = sizeof(struct sockaddr_in);
		ssize_t bytes = recvfrom(sd, &msg, sizeof(MAINFO), 0, (struct sockaddr *)&from, &addrlen);

		if ( bytes < 0 ){
			Log::fatal("relay", "recvfrom() returned %d: %s\n", errno, strerror(errno));
			break;
		}

		/* print received message */
		counter++;
		Log::fatal("relay",  " [%d]  MArC request from %s:%d.\n", counter, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		Log::verbose("relay", "         MP Listens to (UDP) %s:%d\n", msg.address, ntohs(msg.port));
		Log::verbose("relay", "         MArC: %s (%d/%d) database %s %s/%s\n", inet_ntoa(listen_addr), ma_relay_port, ma_control_port, db_name, db_username, strlen(db_password) > 0 ? db_password : "#NO#");

		if ( debug_flag ){
			char* repr = hexdump_str((const char*)&self, sizeof(struct MAINFO));
			Log::debug("relay", "%s", repr);
			free(repr);
		}

		bytes = sendto(sd, &self, sizeof(struct MAINFO), 0, (struct sockaddr*)&from, sizeof(struct sockaddr_in));
		if( bytes < 0 ) {
			Log::fatal("relay", "sendto() returned %d: %s\n", errno, strerror(errno));
			break;
		}
	}
	return 0;
}

#ifdef BUILD_RELAY

int ma_control_port = MA_CONTROL_DEFAULT_PORT;
int ma_relay_port = MA_RELAY_DEFAULT_PORT;
in_addr listen_addr;
in_addr control_addr;
int verbose_flag = 0;
int debug_flag = 0;
FILE* verbose = NULL; /* stdout if verbose is enabled, /dev/null otherwise */
bool volatile keep_running = true;

static struct option long_options[]= {
	{"port", 1, 0, 'p'},
	{"MACip", 1, 0, 'm'},
	{"mport", 1, 0, 's'},
	{"uport", 1, 0, 't'},
	{"database", 1,0 ,'d'},
	{"user",1,0,'u'},
	{"help", 0, 0, 'h'},
	{"verbose", 0, &verbose_flag, 1},
	{"quiet", 0, &verbose_flag, 0},
	{"debug", 0, &debug_flag, 1},
	{0, 0, 0, 0}
};

int main(int argc, char *argv[]){
	register int op;
	int option_index = 0;

	while ( (op = getopt_long(argc, argv, "b:p:m:s:hd:u:v:t:", long_options, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'd':
			strncpy(db_name, optarg, sizeof(db_name));
			db_name[sizeof(db_name)-1] = '\0';
			break;

		case 'u':
			strncpy(db_username, optarg, sizeof(db_username));
			db_username[sizeof(db_username)-1] = '\0';
			break;

		case 'v':
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

		case 'p':
			ma_relay_port = atoi(optarg);
			break;

		case 's':
			db_port = atoi(optarg);
			break;

		case 't':
			ma_control_port = atoi(optarg);
			break;

		case 'm':
			inet_aton(optarg, &control_addr);
			break;

		case 'h':
			printf("help\n");
			printf("usage: %s [options] filename\n",argv[0]);
			printf("  -p, --port     Portnumber to listen [default %d]\n", MA_RELAY_DEFAULT_PORT);
			printf("  -m, --MACip    MA-Controller IP, dotted decimal IPv4. [REQUIRED]\n");
			printf("  -t             MA-Controller port [default %d]\n", MA_CONTROL_DEFAULT_PORT);
			printf("  -s, --mport	 MySQL port number [default 3306]\n");
			printf("  -d, --database Database.\n");
			printf("  -u, --user	 Username.\n");
			printf("  -v, --password Password.\n");
			printf("  -h, --help	 this text\n");
			printf("      --verbose  Verbose output\n");
			printf("      --quiet    Inverse of --verbose\n");
			printf("      --debug    Show debugging output\n");
			exit(0);
			break;

		default:
			fprintf(stderr, "getopt returned character code %d\n", op);
			assert(0 && "declared but unhandled argument");
		}
	}

	if ( control_addr.s_addr == 0 ){
		fprintf(stderr, "You must supply a IP address to the MA-Controller.\n");
		exit(1);
	}

	verbose_flag |= debug_flag;
	verbose = verbose_flag ? stdout : fopen("/dev/null", "w");

	Relay relay;
	relay.init();
	relay.run();
	relay.cleanup();

	return 0;
}

#endif /* BUILD_RELAY */
