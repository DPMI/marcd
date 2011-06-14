/***************************************************************************
                          udpserver.cpp  -  description
                             -------------------
    begin                : Wed Oct 30 2002
    copyright            : (C) 2002 by Anders Ekberg
    email                : anders.ekberg@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

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

#define MAX_MSG 1500

struct MAINFO{
  int version;
  char address[16];
  int port;
  char database[64];
  char user[64];
  char password[64];
  int portUDP;
};

int LOCAL_SERVER_PORT= 1500;
int MYSQL_PORT = 3306;
int MARC_PORT= 1600;

int main(int argc, char *argv[]){
  extern int optind, opterr, optopt;
  register int op;
  int this_option_optind;
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
  
  int sd, rc, n, cliLen,option, counter;
  struct sockaddr_in cliAddr, servAddr;
  char msg[MAX_MSG];
  char *serv=(char*)malloc(17);
  struct MAINFO myInfo,*hisInfo;
  sprintf(myInfo.address,"192.168.0.159");
  sprintf(serv,"255.255.255.255");
  sprintf(myInfo.database,"measproj");
  sprintf(myInfo.user,"genmp");
  sprintf(myInfo.password,"");
  myInfo.port=MYSQL_PORT;
  myInfo.version=2;
  myInfo.portUDP=MARC_PORT;
  option=1;


  for(;;) {
    this_option_optind = optind ? optind : 1;
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


  /* socket creation */
  sd=socket(AF_INET, SOCK_DGRAM, 0);
  if(sd<0) {
    printf("%s: cannot open socket \n",argv[0]);
    exit(1);
  }

  setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int));
  setsockopt(sd,SOL_SOCKET,SO_BROADCAST,(void*)1,sizeof(int));
  
  /* bind local server port */
  servAddr.sin_family = AF_INET;
  inet_aton(serv,&servAddr.sin_addr);
  servAddr.sin_port = htons(LOCAL_SERVER_PORT);

  printf("Listens to %s:%d\n",inet_ntoa(servAddr.sin_addr),ntohs(servAddr.sin_port));
  if( bind (sd, (struct sockaddr *) &servAddr,sizeof(servAddr))<0){
    printf("%s: cannot bind port number %d \n",
	   argv[0], LOCAL_SERVER_PORT);
    exit(1);
  }
  printf("%s: Waiting for data on port UDP %u\n",argv[0],LOCAL_SERVER_PORT);
  printf("This is the info:\n\tMArC: %s (%d/%d)\n\tDatabase: %s\n\tUser: %s\n\tPassword: %s\n",myInfo.address, myInfo.port, myInfo.portUDP, myInfo.database, myInfo.user, myInfo.password);

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
		printf("\t MArC: %s (%d/%d) database %s %s/",myInfo.address, myInfo.port, myInfo.portUDP, myInfo.database, myInfo.user, myInfo.password);
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


