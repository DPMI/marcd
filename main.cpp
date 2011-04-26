/***************************************************************************
                          MARcD.cpp  -  description
                             -------------------
    begin                : Mon 28 Nov, 2005
    copyright            : (C) 2005 by Patrik Arlos
    email                : patrik.arlos@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <libmarc/libmarc.h>

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
#include <errno.h>

#include <mysql.h>
#include <strings.h>
#define IFHWADDRLEN 6
#define MAX_MSG 1500
#define LOCAL_SERVER_PORT 1600;
#define ETH_ALEN 6

int convMySQLtoFPI(struct FPI *rule,  MYSQL_RES *result);// 
static char hex_string[IFHWADDRLEN * 3] = "00:00:00:00:00:00";

char query[2000];
MYSQL_RES *result;
MYSQL_ROW row;
MYSQL *connection, mysql;
int state;

void MP_Init(marc_context_t marc, MPinitialization* init, struct sockaddr* from);
void MP_Status(int sd, struct sockaddr from, char buffer[1500]);
void MP_GetFilter(int sd, struct sockaddr from, char buffer[1500]);
void MP_VerifyFilter(int sd, struct sockaddr from, char buffer[1500]);

char *hexdump_address (char address[IFHWADDRLEN]);
int convMySQLtoFPI(struct FPI *rule,  MYSQL_RES *result);
int inet_atoP(char *dest,char *org);
int inet_aEtoP(char *dest,char *org);
void printFilter(struct FPI *F);

/**
 * Dump the content of data as hexadecimal (and its ascii repr.)
 */
static void hexdump(FILE* fp, const char* data, size_t size){
  const size_t align = size + (size % 16);
  fputs("[0000]  ", fp);
  for( unsigned int i=0; i < align; i++){
    if ( i < size ){
      fprintf(fp, "%02X ", data[i] & 0xff);
    } else {
      fputs("   ", fp);
    }
    if ( i % 4 == 3 ){
      fputs("   ", fp);
    }
    if ( i % 16 == 15 ){
      fputs("    |", fp);
      for ( unsigned int j = i-15; j<=i; j++ ){
        char ch = data[j];

        if ( j >= size ){
          ch = ' ';
        } else if ( !isprint(data[j]) ){
          ch = '.';
        }

        fputc(ch, fp);
      }
      fputs("|", fp);
      if ( (i+1) < align){
        fprintf(fp, "\n[%04X]  ", i+1);
      }
    }
  }
  printf("\n");
}

int main(int argc, char *argv[]){
  extern int opterr, optopt;
  register int op;
  int port;
  int option_index;
  int requiredARG=0;
  static struct option long_options[]= {
    {"help", 0, 0, 'v'},
    {"host",1,0,'h'},
    {"database",1,0,'d'},
    {"user",1,0,'u'},
    {"password",1,0,'p'},
    {0, 0, 0, 0}
  };
  
  char host_address[16];
  int db_port=MYSQL_PORT;
  char database[64];
  char user[64];
  char password[64];

  bzero(host_address,16);
  bzero(database,64);
  bzero(user,64);
  bzero(password,64);

  opterr=0;
  optopt=0;


  port=LOCAL_SERVER_PORT;
  for(;;) {
    option_index = 0;
    
    op = getopt_long  (argc, argv, "h:d:u:p:v",long_options, &option_index);
    if (op == -1)
      break;
    
    switch (op)        {
      case 'v':
	printf("help\n");
	printf("usage: %s [options] filename\n",argv[0]);
	printf("-v or --help      Tis text\n");
	printf("-h or --host      IP of DB server.\n");
	printf("-d or --database  Database name.\n");
	printf("-u or --user      Username in database.\n");
	printf("-p or --password  Password for user.\n");
	exit(0);
	break;	
    case 'h':
      memcpy(host_address,optarg,strlen(optarg));
      requiredARG++;
      printf("DB ip = %s / %zd - %zd.\n",host_address,strlen(optarg),strlen(host_address) );
      break;
    case 'd':
      memcpy(database,optarg,strlen(optarg));
      requiredARG++;
      printf("DB database = %s.\n",database);
      break;
    case 'u':
      memcpy(user,optarg,strlen(optarg));
      requiredARG++;
      printf("DB username = %s.\n",user);
      break;
    case 'p':
      memcpy(password,optarg,strlen(optarg));
      requiredARG++;
      printf("DB password = %s.\n",password);
      break;
      
    default:
      printf ("?? getopt returned character code 0%o ??\n", op);
    }
  }
  /*
    
  if(requiredARG<4){
    printf("You must supply a database info..\n");
    exit(1);
  }
  */

  printf("MySQL: %s:%d (%s/%s) Database %s.\n",host_address,db_port,user,password,database);
  mysql_init(&mysql);
  connection = mysql_real_connect(&mysql, host_address, user, password, database,db_port,0,0);
  /* check connection */
  if( connection == NULL) {
    puts(mysql_error(&mysql));
    exit(1);
  }

  int ret;
  marc_context_t marc;
  if ( (ret=marc_init_server(&marc, port)) != 0 ){
    fprintf(stderr, "marc_init_server() returned %d: %s\n", ret, strerror(ret));
    return 1;
  }

  while (1){
    MPMessage event;
    struct sockaddr from;
    struct timeval timeout = {1, 0}; /* 1 sec timeout */
    size_t bytes;
    switch ( (ret=marc_poll_event(marc, &event, &bytes, &from, &timeout)) ){
    case EAGAIN: /* delivered if using a timeout */
    case EINTR:  /* interuped */
      continue;
      
    case 0:
      break;
      
    default:
      fprintf(stderr, "marc_poll_event() returned %d: %s\n", ret, strerror(ret));
      return 1;
    }

    switch ( event.type ){
    case MP_CONTROL_INIT_EVENT:
      MP_Init(marc, &event.init, &from);
      break;
    
    default:
      fprintf(stderr, "not handling message of type %d\n", event.type);
    }
  }

  return 0;
}


      // msgPtr=(struct Generic*)(messageBuffer);
      // printf("\nType  = %d \n", ntohl(msgPtr->type));
      // switch(ntohl(msgPtr->type)){
      // case 1:
      // 	MP_Init(sd, from, messageBuffer);
      // 	break;
      // case 2:
      // 	MP_Status(sd,from, messageBuffer);
      // 	break;
      // case 3:
      // 	MP_GetFilter(sd,from, messageBuffer);
      // 	break;
      // case 6:
      // 	MP_VerifyFilter(sd,from, messageBuffer);
      // 	break;

      // default:
      // 	printf("Unknown message.\n");
      // 	break;
      // }

void MP_Init(marc_context_t marc, MPinitialization* MPinit, struct sockaddr* from){
  struct sockaddr_in MPadr;
  struct MPauth MPauth;
  int ret;

  MPauth.type = MP_CONTROL_AUTHORIZE_EVENT;
  memset(MPauth.MAMPid, 0, 16);

  printf("MPinit\n");
  printf("      .type= %d \n",MPinit->type);
  printf("      .mac = %s \n",hexdump_address(MPinit->mac));
  printf("      .name= %s \n",MPinit->hostname);
  memcpy(&MPadr.sin_addr.s_addr, MPinit->ipaddress,sizeof(struct in_addr));
  printf("      .ipaddress = %s \n", inet_ntoa(MPadr.sin_addr));
  printf("      .port = %d \n", ntohs(MPinit->port));
  printf("      .maxFilters = %d \n",ntohs(MPinit->maxFilters));
  printf("      .noCI = %d \n", ntohs(MPinit->noCI));
  printf("      .MAMPid = %s \n", MPinit->MAMPid);

  if ( mysql_ping(connection) != 0 ){
    fprintf(stderr, "Connection lost to mysql database: %s\n", mysql_error(connection));
    abort();
  }

  sprintf(query, "SELECT MAMPid FROM measurementpoints WHERE mac='%s' AND name='%s'",hexdump_address(MPinit->mac),MPinit->hostname);
  if ( mysql_query(connection,query) != 0 ) {
    fprintf(stderr, "Failed to execute mysql query: %s\nThe query was: %s\n", mysql_error(connection), query);
    return;
  }
  
  result=mysql_store_result(connection);
  if(mysql_num_rows(result)==0){ /* We are a new MP..  */
    printf("This is an unregisterd MP.");
    mysql_free_result(result);

    sprintf(query, "INSERT INTO measurementpoints SET name='%s',ip='%s',port='%d',mac='%s',maxFilters=%d,noCI=%d"
	    ,MPinit->hostname
	    ,inet_ntoa(MPadr.sin_addr)
	    ,ntohs(MPinit->port)
	    ,hexdump_address((char*)MPinit->mac)
	    ,ntohs(MPinit->maxFilters)
	    ,ntohs(MPinit->noCI));
    if ( mysql_query(connection,query) != 0 ) {
      fprintf(stderr, "Failed to execute mysql query: %s\nThe query was: %s\n", mysql_error(connection), query);
      return;
    }

    return;
  }

  char MAMPid[16];
  row = mysql_fetch_row(result);
  strncpy(MAMPid, row[0], 16);
  mysql_free_result(result);

  printf("MAMPid = %s (%zd) \n", MAMPid, strlen(MAMPid));
  memcpy(MPauth.MAMPid, MAMPid, 16);

  /* Authorize */
  if ( (ret=marc_push_event(marc, (MPMessage*)&MPauth, from)) != 0 ){
    fprintf(stderr, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
    return;
  }

  if( strlen(MAMPid) == 0){ // The MP exists, but isnt authorized.
    return;
  }

  /* Lets check if we have any filters waiting for us? */
  sprintf(query, "SELECT * from %s_filterlist ORDER BY 'filter_id' ASC ",MAMPid);
  if ( mysql_query(connection,query) != 0 ) {
    fprintf(stderr, "Failed to execute mysql query: %s\nThe query was: %s\n", mysql_error(connection), query);
    return;
  }

  result = mysql_store_result(connection);
  int rows = (int)mysql_num_rows(result);
  printf("MP %s has %d filters assigned.\n", MAMPid, rows);
  
  /*process each row*/  
  for( int n=0; n < rows; n++ ){
    struct FPI fpi;
    struct MPFilter MPfilter;

    convMySQLtoFPI(&fpi, result);
    struct Filter* filter = &fpi.filter;
      
    MPfilter.type = MP_FILTER_EVENT;
    sprintf(MPfilter.MAMPid, "%s", MAMPid);
    marc_filter_pack(filter, &MPfilter.filter);
      
    printf("Sending Filter %d to to MP %s.\n", filter->filter_id, MPfilter.MAMPid);
    hexdump(stdout, (char*)&MPfilter, sizeof(struct MPFilter));

    if ( (ret=marc_push_event(marc, (MPMessage*)&MPfilter, from)) != 0 ){
      fprintf(stderr, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
      return;
    }    
  }

  /* free the result set */
  mysql_free_result(result);

  printf("MP_init done.\n");
  return;
}

void MP_Status(int sd, struct sockaddr from, char *buffer){
  char statusQ[2000];
  char *query;
  query=statusQ;
  bzero(statusQ,sizeof(statusQ));
  struct MPstatus* MPstat=(struct MPstatus*)buffer;
  sprintf(statusQ,"INSERT INTO %s_CIload SET noFilters='%d', matchedPkts='%d' %s",MPstat->MAMPid,ntohl(MPstat->noFilters),ntohl(MPstat->matched), MPstat->CIstats);

  printf("MP_status():\n%s\n",query);
  state=mysql_query(connection,query);
  if(state != 0) {
    puts(mysql_error(connection));
  }
  printf("Status added to Database.\n");
  return;
}


void MP_GetFilter(int sd, struct sockaddr from, char *buffer){
  char statusQ[2000];
  char *query;
  int slen;
  socklen_t fromlen = sizeof(from);
  struct FPI *newRule;
  query=statusQ;
  bzero(statusQ,sizeof(statusQ));
  struct MPFilter* filter=(struct MPFilter*)buffer;
  sprintf(statusQ,"SELECT * FROM %s_filterlist WHERE filter_id='%d'",filter->MAMPid,filter->filter.filter_id);

  printf("MP_GetFilter():\n%s\n",query);
  state=mysql_query(connection,query);
  if(state != 0) {
    puts(mysql_error(connection));
  }
  printf("Got info from Db.\n");
  result = mysql_store_result(connection);
  newRule=(struct FPI*)calloc(1, sizeof(struct FPI));
  convMySQLtoFPI(newRule,result);
  printf("Sending this filter.\n");
  printFilter(newRule);
  memcpy(&filter->filter,&newRule->filter,sizeof(struct FilterPacked));

  printf("Sending Resonse to MP_init. foo\n");
  hexdump(stdout, (const char*)filter, sizeof(struct MPFilter));
  slen=sendto(sd,filter,sizeof(struct MPFilter),0,&from,fromlen);
  printf("Sent %d bytes.\n",slen);

  return;
}



void MP_VerifyFilter(int sd, struct sockaddr from, char *buffer){
  char statusQ[2000];
  char *query;
  query=statusQ;
  bzero(statusQ,sizeof(statusQ));
  struct MPVerifyFilter* MyVerify=(struct MPVerifyFilter*)buffer;
  struct FilterPacked* F = &MyVerify->filter;
  if(MyVerify->flags==0) {
    sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', comment='NOT PRESENT'", MyVerify->MAMPid,MyVerify->filter_id); 
  } else {
    sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', ind='%d', CI_ID='%s', VLAN_TCI='%d', VLAN_TCI_MASK='%d',ETH_TYPE='%d', ETH_TYPE_MASK='%d',ETH_SRC='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',ETH_SRC_MASK='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', ETH_DST='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', ETH_DST_MASK='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',IP_PROTO='%d', IP_SRC='%s', IP_SRC_MASK='%s', IP_DST='%s', IP_DST_MASK='%s', SRC_PORT='%d', SRC_PORT_MASK='%d', DST_PORT='%d', DST_PORT_MASK='%d', TYPE='%d', CAPLEN='%d', consumer='%d'",
	    MyVerify->MAMPid,F->filter_id,F->index,F->CI_ID,F->VLAN_TCI,F->VLAN_TCI_MASK,
	    F->ETH_TYPE,F->ETH_TYPE_MASK, 
	    (unsigned char)(F->ETH_SRC.ether_addr_octet[0]),(unsigned char)(F->ETH_SRC.ether_addr_octet[1]),(unsigned char)(F->ETH_SRC.ether_addr_octet[2]),(unsigned char)(F->ETH_SRC.ether_addr_octet[3]),(unsigned char)(F->ETH_SRC.ether_addr_octet[4]),(unsigned char)(F->ETH_SRC.ether_addr_octet[5]),
	    (unsigned char)(F->ETH_SRC_MASK[0]),(unsigned char)(F->ETH_SRC_MASK[1]),(unsigned char)(F->ETH_SRC_MASK[2]),(unsigned char)(F->ETH_SRC_MASK[3]),(unsigned char)(F->ETH_SRC_MASK[4]),(unsigned char)(F->ETH_SRC_MASK[5]),

	    (unsigned char)(F->ETH_DST.ether_addr_octet[0]),(unsigned char)(F->ETH_DST.ether_addr_octet[1]),(unsigned char)(F->ETH_DST.ether_addr_octet[2]),(unsigned char)(F->ETH_DST.ether_addr_octet[3]),(unsigned char)(F->ETH_DST.ether_addr_octet[4]),(unsigned char)(F->ETH_DST.ether_addr_octet[5]),
	    (unsigned char)(F->ETH_DST_MASK[0]),(unsigned char)(F->ETH_DST_MASK[1]),(unsigned char)(F->ETH_DST_MASK[2]),(unsigned char)(F->ETH_DST_MASK[3]),(unsigned char)(F->ETH_DST_MASK[4]),(unsigned char)(F->ETH_DST_MASK[5]),
	    F->IP_PROTO,
	    F->IP_SRC,F->IP_SRC_MASK,F->IP_DST,F->IP_DST_MASK,
	    F->SRC_PORT,F->SRC_PORT_MASK,F->DST_PORT,F->DST_PORT_MASK,
	    F->TYPE, 
	    F->CAPLEN,
	    F->consumer);
      
    if(F->TYPE==1) {
      sprintf(query,"%s, DESTADDR='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X' ",query, (unsigned char)(F->DESTADDR[0]),(unsigned char)(F->DESTADDR[1]),(unsigned char)(F->DESTADDR[2]),(unsigned char)(F->DESTADDR[3]),(unsigned char)(F->DESTADDR[4]),(unsigned char)(F->DESTADDR[5]));
    } else {
      sprintf(query,"%s, DESTADDR='%s' ",query, F->DESTADDR);
    }
  }

  printf("MP_VerifyFilter():\n%s\n",query);
  state=mysql_query(connection,query);
  if(state != 0) {
    printf("%s\n", mysql_error(connection));
  }

  return;
}


char *hexdump_address (char address[IFHWADDRLEN]){
  int i;

  for (i = 0; i < IFHWADDRLEN - 1; i++) {
    sprintf (hex_string + 3*i, "%2.2X:", (unsigned char) address[i]);
  }  
  sprintf (hex_string + 15, "%2.2X", (unsigned char) address[i]);
  return (hex_string);
}


int convMySQLtoFPI(struct FPI *fpi,  MYSQL_RES *result){
  struct Filter* rule = &fpi->filter;

  char *pos=0;
  MYSQL_ROW row;  
  row=mysql_fetch_row(result);
  rule->filter_id=atoi(row[0]);
  rule->index=atoi(row[1]);
  strncpy(rule->CI_ID,row[2],8);
  rule->VLAN_TCI=atol(row[3]);
  rule->VLAN_TCI_MASK=atol(row[4]);
  rule->ETH_TYPE=atol(row[5]);
  rule->ETH_TYPE_MASK=atol(row[6]);
  
  
  rule->IP_PROTO=atoi(row[11]);
  strncpy((char*)rule->IP_SRC,row[12],16);
  strncpy((char*)rule->IP_SRC_MASK,row[13],17);
  strncpy((char*)rule->IP_DST,row[14],18);
  strncpy((char*)rule->IP_DST_MASK,row[15],19);
  
  rule->SRC_PORT=atoi(row[16]);
  rule->SRC_PORT_MASK=atoi(row[17]);
  rule->DST_PORT=atoi(row[18]);
  rule->DST_PORT_MASK=atoi(row[19]);
  rule->consumer=atoi(row[20]);
  
  inet_atoP((char*)rule->ETH_SRC.ether_addr_octet,row[7]);
  inet_atoP((char*)rule->ETH_SRC_MASK,row[8]);
  inet_atoP((char*)rule->ETH_DST.ether_addr_octet,row[9]);
  inet_atoP((char*)rule->ETH_DST_MASK,row[10]);

  rule->TYPE=atoi(row[22]);
  rule->CAPLEN=atoi(row[23]);

  switch(rule->TYPE){
  case 3: // TCP
  case 2: // UDP
    // DESTADDR is ipaddress:port
    strncpy((char*)rule->DESTADDR,row[21],22);
    pos=index((char*)rule->DESTADDR,':');
    if(pos!=NULL) {
      *pos=0;
      rule->DESTPORT=atoi(pos+1);
    } else {
      rule->DESTPORT=0x0810;
    }
    break;
  case 1: // Ethernet
    inet_atoP((char*)rule->DESTADDR,row[21]);
    break;
  case 0: // File
    strncpy((char*)rule->DESTADDR,row[21],22);
    break;
  }

  return 1;
}


/* Convert a string ip with dotted decimal to a hexc.. */
int inet_atoP(char *dest,char *org){
  char tmp[3];
  tmp[2]='\0';
  int j,k;
  j=k=0;
  int t;
  for(j=0;j<ETH_ALEN;j++){
    strncpy(tmp,org+k,2);
    t=(int)strtoul(tmp,NULL,16);
    *(dest+j)=t;
    k=k+2;
  }
  return 1;
}

/* Convert a string Ethernet to hex. */
int inet_aEtoP(char *dest,char *org){
  char tmp[3];
  tmp[2]='\0';
  int j,k;
  j=k=0;
  int t;
  for(j=0;j<ETH_ALEN;j++){
    strncpy(tmp,org+k,2);
    t=(int)strtoul(tmp,NULL,16);
    *(dest+j)=t;
    printf("%s --> %02x \n",tmp, t);
    k=k+2;
  }
  return 1;
}


void printFilter(struct FPI *fpi){
  struct Filter* F = &fpi->filter;
  printf("CTRL PRINT FILTER\n");
  printf("filter_id    :%d\n",F->filter_id);
  printf("consumer     :%d\n",F->consumer);
  switch(F->TYPE){
  case 3:
  case 2:
    printf("DESTADDRESS  :%s TYPE : %d\n",F->DESTADDR, F->TYPE);
    printf("DESTPORT     :%d \n",F->DESTPORT);
    break;
  case 1:
    printf("DESTADDRESS  :%02X:%02X:%02X:%02X:%02X:%02X  TYPE    :%d\n",F->DESTADDR[0],F->DESTADDR[1],F->DESTADDR[2],F->DESTADDR[3],F->DESTADDR[4],F->DESTADDR[5], F->TYPE);
    break;
  case 0:
    printf("DESTFILE     :%s TYPE %d \n",F->DESTADDR, F->TYPE);
    break;
  }
  printf("CAPLEN       :%d\n",F->CAPLEN);
  printf("index        :%d\n",F->index);
  printf("CI_ID        :");
  if(F->index&512)
    printf("%s\n",F->CI_ID);
  else 
    printf("NULL\n");
  
  printf("VLAN_TCI     :");
  if(F->index&256){
    printf("%d\n",F->VLAN_TCI);
    printf("VLAN_TCI_MASK:%d\n",F->VLAN_TCI_MASK);
  }  else{
    printf("NULL\n");
    printf("VLAN_TCI_MASK:NULL\n");
  }

  printf("ETH_TYPE     :");
  if(F->index&128){
    printf("%d\n",F->ETH_TYPE);
    printf("ETH_TYPE_MASK: %d\n",F->ETH_TYPE_MASK);
  }  else {
    printf("NULL\n");
    printf("ETH_TYPE_MASK:NULL\n");
  }
  
  printf("ETH_SRC      :");
  if(F->index&64){
    printf("%s\n",hexdump_address((char*)F->ETH_SRC.ether_addr_octet));
    printf("ETH_SRC_MASK :%s\n",hexdump_address((char*)F->ETH_SRC_MASK));
  } else {
    printf("NULL\n");
    printf("ETH_SRC_MASK:NULL\n");
  }

  printf("ETH_DST      :");
  if(F->index&32){
    printf("%s\n",(char*)F->ETH_DST.ether_addr_octet);
    printf("ETH_DST_MASK:%s\n",F->ETH_DST_MASK);
  } else {
    printf("NULL\n");
    printf("ETH_DST_MASK :NULL\n");
  }
  
  printf("IP_PROTO     :");
  if(F->index&16)
    printf("%d\n",F->IP_PROTO);
  else
    printf("NULL\n");

  printf("IP_SRC       :");
  if(F->index&8){
    printf("%s\n",(char*)F->IP_SRC);
    printf("IP_SRC_MASK  :%s\n",F->IP_SRC_MASK);
  } else {
    printf("NULL\n");
    printf("IP_SRC_MASK:NULL\n");
  }

  printf("IP_DST       :");
  if(F->index&4){
    printf("%s\n",(char*)F->IP_DST);
    printf("IP_DST_MASK  :%s\n",F->IP_DST_MASK);
  } else {
    printf("NULL\n");
    printf("IP_DST_MASK:NULL\n");
  }

  printf("PORT_SRC     :");
  if(F->index&2){
    printf("%d\n",F->SRC_PORT);
    printf("PORT_SRC_MASK:%d\n",F->SRC_PORT_MASK);
  } else {
    printf("NULL\n");
    printf("PORT_SRC_MASK:NULL\n");
  }

  printf("PORT_DST     :");
  if(F->index&1){
    printf("%d\n",F->DST_PORT);
    printf("PORT_DST_MASK:%d\n",F->DST_PORT_MASK);
  } else {
    printf("NULL\n");
    printf("PORT_DST_MASK:NULL\n");
  }
  

}
