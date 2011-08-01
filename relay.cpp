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
#include "database.h"

#include <libmarc/log.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>

#define MAX_MSG 1500

extern FILE* verbose;
extern const char* iface;
extern int ma_control_port;
extern int ma_relay_port;
extern in_addr listen_addr;
extern bool volatile keep_running;

struct MAINFO {
  int version;
  char address[16];
  int port;
  char database[64];
  char user[64];
  char password[64];
  int portUDP;
};

Relay::Relay()
  : sd(0) {

}

int Relay::init(){
  /* socket creation */
  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if ( sd < 0 ) {
    logmsg(stderr, "cannot open socket (%d): %s\n", errno, strerror(errno));
    return 1;
  }

  int on = 1;
  setsockopt(sd,SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
  setsockopt(sd,SOL_SOCKET, SO_BROADCAST, &on, sizeof(int));
  
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;

  /* Find appropriate broadcast address */
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if ( iface ){
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    
    if(ioctl(sd, SIOCGIFBRDADDR, &ifr) == -1 ) {
      logmsg(stderr, "Could not get broadcast address for %s: %s", iface, strerror(errno));
      return 1;
    }

    memcpy(&addr, &ifr.ifr_broadaddr, sizeof(ifr.ifr_broadaddr));
  }

  /* bind local server port */
  addr.sin_port = htons(ma_relay_port);
  logmsg(stderr, "[ relay ] Listens to %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
  if ( bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ){
    logmsg(stderr, "[ relay ] cannot bind port number %d\n", ma_relay_port);
    return 1;
  }

  logmsg(verbose, "[ relay ] Relay info:\n");
  logmsg(verbose, "[ relay ]   MArC: %s (%d/%d)\n", inet_ntoa(listen_addr), ma_relay_port, ma_control_port);
  logmsg(verbose, "[ relay ]   Database: %s\n", db_name);
  logmsg(verbose, "[ relay ]   User: %s\n", db_username);
  logmsg(verbose, "[ relay ]   Password: %s\n", db_password);

  return 0;
}

int Relay::cleanup(){
  logmsg(stderr, "[ relay ] Thread finished.\n");
  return 0;
}

int Relay::run(){
  int counter = 0;
  MAINFO msg, self;
  struct sockaddr_in from;

  self.version = 2;
  strncpy(self.address, inet_ntoa(listen_addr), 16);
  self.port = MYSQL_PORT;
  strncpy(self.database, db_name, 64);
  strncpy(self.user, db_username, 64);
  strncpy(self.password, db_password, 64);
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
      logmsg(stderr, "[ relay ] recvfrom() returned %d: %s\n", errno, strerror(errno));
      break;
    }

    /* print received message */
    counter++;
    logmsg(stderr,  "[ relay ]  [%d]  MArC request from %s:%d.\n", counter, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    logmsg(verbose, "[ relay ]          MP Listens to (UDP) %s:%d\n", msg.address, ntohs(msg.port));
    logmsg(verbose, "[ relay ]          MArC: %s (%d/%d) database %s %s/%s\n", inet_ntoa(listen_addr), ma_relay_port, ma_control_port, db_name, db_username, strlen(db_password) > 0 ? db_password : "#NO#");

    bytes = sendto(sd, &self, sizeof(struct MAINFO), 0, (struct sockaddr*)&from, sizeof(struct sockaddr_in));
    if( bytes < 0 ) {
      logmsg(stderr, "[ relay ] sendto() returned %d: %s\n", errno, strerror(errno));
      break;
    }
  }
  return 0;
}

#ifdef BUILD_RELAY
int main(int argc, char *argv[]){
  register int op;
  int option_index;
  int requiredARG=0;
  static struct option long_options[]= {
    {"bcast",1,0,'b'},
    {"port", 1, 0, 'p'},
    {"MACip", 1, 0, 'm'},
    {"mport", 1, 0, 's'},
    {"uport", 1, 0, 't'},
    {"database", 1,0 ,'d'},
    {"user",1,0,'u'},
    {"help", 0, 0, 'h'},
    {0, 0, 0, 0}
  };
  
  int sd, n, cliLen, counter;
  struct sockaddr_in cliAddr, servAddr;

  char *serv=(char*)malloc(17);
  struct MAINFO myInfo,*hisInfo;
  sprintf(myInfo.address,"192.168.0.159");
  sprintf(serv,"255.255.255.255");
  sprintf(myInfo.database,"measproj");
  sprintf(myInfo.user,"genmp");
  memset(myInfo.password, 0, 64);
  myInfo.port=MYSQL_PORT;
  myInfo.version=2;
  myInfo.portUDP=MARC_PORT;

  for(;;) {
    option_index = 0;
    
    op = getopt_long  (argc, argv, "b:p:m:shd:u:v:t:",
		       long_options, &option_index);
    if (op == -1)
      break;
    
    switch (op)        {
      case 'b':
	free(serv);
	serv=(char*)malloc(strlen(optarg)+1);
	strcpy(serv,optarg);
	break;

      case 'd':
	bzero(myInfo.database,sizeof(myInfo.database));
	strncpy(myInfo.database,optarg,64);
	break;

      case 'u':
	bzero(myInfo.user,sizeof(myInfo.user));
	strncpy(myInfo.user,optarg,64);
	break;

      case 'v':
	bzero(myInfo.password,sizeof(myInfo.password));
	strncpy(myInfo.password,optarg,64);
	break;

      case 'p':
	LOCAL_SERVER_PORT=atoi(optarg);
	break;

      case 'q':
	MYSQL_PORT=atoi(optarg);
	break;
      case 't':
	MARC_PORT=atoi(optarg);
	break;
	
      case 'm':
	bzero(myInfo.address,sizeof(myInfo.address));
	strncpy(myInfo.address,optarg,16);
	requiredARG=1;
	break;
	
      case 'h':
	printf("help\n");
	printf("usage: %s [options] filename\n",argv[0]);
	printf("-b or --bcast    Broadcast address to listen [default 255.255.255.255].\n");
	printf("-p or --port     Portnumber to listen [default 1500]\n");
	printf("-m or --MACip    MA-Controller IP, dotted decimal IPv4. [REQUIRED]\n");
	printf("-s or --mport    MySQL port number [default 3306]\n");
	printf("-d or --database Database.\n");
	printf("-u or --user     Username.\n");
	printf("-v or --password Password.\n");
	printf("-h or --help     this text\n");
	exit(0);
	break;	
      default:
	printf ("?? getopt returned character code 0%o ??\n", op);
    }
  }

  if(requiredARG==0){
    printf("You must supply a IP address to the MA-Controller.\n");
    free(serv);
    exit(1);
  }

  Relay relay;
  relay.init();
  relay.run();
  relay.cleanup();

  counter=0;
  /* server infinite loop */
  for(;;)
     {

        /* init buffer */
        memset(msg,0x0,MAX_MSG);

        /* receive message */
        cliLen = sizeof(cliAddr);
        n = recvfrom(sd, msg, MAX_MSG, 0, (struct sockaddr *) &cliAddr,(socklen_t*) &cliLen);

        if(n<0){
        /*  printf("%s: cannot receive data \n",argv[0]); */
          continue;
        } else {
	        /* print received message */
       	 	counter++;
       	 	hisInfo=(struct MAINFO*)msg;
       		printf("[%d]\t MArC request from %s:%d.\n",counter,inet_ntoa(cliAddr.sin_addr),ntohs(cliAddr.sin_port));
		printf("\t MP Listens to (UDP) %s:%d\n",hisInfo->address,ntohs(hisInfo->port));
		printf("\t MArC: %s (%d/%d) database %s %s/",myInfo.address, myInfo.port, myInfo.portUDP, myInfo.database, myInfo.user);
		if(strlen(myInfo.password)==0){
		  printf("#NO#\n");
		} else {
		  printf("%s\n", myInfo.password);
		}
	}
	n=sendto(sd, &myInfo, sizeof(struct MAINFO),0,(struct sockaddr*)&cliAddr,sizeof(cliAddr));
	if(n==-1) {
	  perror("Cannot send reply.\n");
	  exit(1);
	}
//	printf("Sent %d bytes.\n",n);
      }/* end of server infinite loop */

return 0;

}

#endif /* BUILD_RELAY */
