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

#include <libmarc/libmarc.h>
#include <libmarc/log.h>
#include <libmarc/version.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <errno.h>

#include <unistd.h>
#include <pwd.h>
#include <grp.h>
 
#include <mysql.h>
#include <errmsg.h> /* from mysql */

#define LOCAL_SERVER_PORT 1600;
#define LOG_EVENT(x, mampid)							\
  logmsg(verbose, x " from %s:%d (MAMPid: %s)\n", \
  inet_ntoa(((struct sockaddr_in*)from)->sin_addr), ntohs(((struct sockaddr_in*)from)->sin_port), mampid)

enum MPStatusEnum {
  MP_STATUS_NOT_AUTH,
  MP_STATUS_IDLE,
  MP_STATUS_CAPTURE,
  MP_STATUS_STOPPED,
  MP_STATUS_DISTRESS,
};

static MYSQL connection;
static char db_hostname[64] = "localhost";
static int  db_port = MYSQL_PORT;
static char db_name[64] = {0,};
static char db_username[64] = {0,};
static char db_password[64] = {0,};

char* rrdpath;
static int verbose_flag = 0;
static int debug_flag = 0;
FILE* verbose = NULL; /* stdout if verbose is enabled, /dev/null otherwise */

static int drop_priv_flag = 1;
static uid_t drop_uid = -1;
static gid_t drop_gid = -1;

static void MP_Init(marc_context_t marc, MPinitialization* init, struct sockaddr* from);
static void MP_Status(marc_context_t marc, MPstatus* MPstat, struct sockaddr* from);
void MP_Status2_reset(const char* MAMPid, int noCI);
void MP_Status2(marc_context_t marc, MPstatus2* MPstat, struct sockaddr* from);
static void MP_GetFilter(marc_context_t marc, MPFilterID* filter, struct sockaddr* from);
static void MP_VerifyFilter(int sd, struct sockaddr from, char buffer[1500]);
static void MP_Distress(marc_context_t marc, const char* mampid, struct sockaddr* from);

static void mp_set_status(const char* mampid, enum MPStatusEnum status);

static int connect();
static int convMySQLtoFPI(struct FPI *rule,  MYSQL_RES *result);
static int inet_atoP(char *dest,char *org);

enum LongFlags {
  FLAG_DATADIR = 256,
  FLAG_USER,
  FLAG_GROUP,
};

int main(int argc, char *argv[]){
  extern int opterr, optopt;
  int port = LOCAL_SERVER_PORT;
  static struct option long_options[]= {
    {"help", 0, 0, 'v'},
    {"database",1,0, 'd'},
    {"dbhost",1,0,'h'},
    {"dbusername",1,0,'u'},
    {"dbpassword",1,0,'p'},
    {"verbose", 0, &verbose_flag, 1},
    {"debug", 0, &debug_flag, 1},
    {"datadir", 1, 0, FLAG_DATADIR},

    /* priviledge dropping */
    {"drop", 0, &drop_priv_flag, 1},
    {"no-drop", 0, &drop_priv_flag, 0},
    {"user", 1, 0, FLAG_USER},
    {"group", 1, 0, FLAG_GROUP},

    {0, 0, 0, 0}
  };
  
  opterr=0;
  optopt=0;

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

  printf("MArCd " VERSION " (libmarc-" LIBMARC_VERSION ")\n");

  for(;;) {
    int option_index = 0;
    
    int op = getopt_long  (argc, argv, "h:u:p:v", long_options, &option_index);
    if (op == -1)
      break;
    
    switch (op)        {
    case 0: /* long opt */
      break;

    case 'v':
      printf("(C) 2004 patrik.arlos@bth.se\n");
      printf("(C) 2011 david.sveningsson@bth.se\n");
      printf("Usage: %s [OPTIONS] DATABASE\n",argv[0]);
      printf("Database options\n");
      printf("  -h, --dbhost      MySQL database host. [Default: localhost]\n");
      printf("      --database    Database name.\n");
      printf("  -u, --dbusername  Database username. [Default: current user]\n");
      printf("  -p, --dbpassword  Database password, use '-' to read password\n"
	     "                    from stdin. [Default: none]\n");
      printf("\n");
      printf("Priviledge options\n");
      printf("      --drop        Drop priviledges. [default]\n");
      printf("      --no-drop     Inverse of --drop.\n");
      printf("      --user USER   Change UID to this user. [default: marc]\n");
      printf("      --group GROUP Change GID to this group. [default: marc]\n");
      printf("\n");
      printf("Other\n");
      printf("      --verbose     Verbose output.\n");
      printf("      --debug       Show extra debugging output, including hexdump\n"
	     "                    of all incomming and outgoing messages. Implies\n"
	     "                    verbose output.\n");
      printf("      --help        This text\n");
      return 0;
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

  /* redirect output */
  marc_set_output_handler(logmsg, vlogmsg, stderr, verbose);

  /* initialize mysql */
  mysql_init(&connection);
  if ( !connect() ){
    return 1;
  }

  if ( access(rrdpath, W_OK) != 0 ){
    logmsg(stderr, "Need write persmission to data dir: %s\n", rrdpath);
    return 1;
  }
  logmsg(stderr, "Datadir: %s\n", rrdpath);

  /* initialize libmarc */
  int ret;
  marc_context_t marc;
  if ( (ret=marc_init_server(&marc, port)) != 0 ){
    logmsg(stderr, "marc_init_server() returned %d: %s\n", ret, strerror(ret));
    return 1;
  }

  /* drop priviledges */
  if ( drop_priv_flag ){
    if ( getuid() == 0 ){
      logmsg(stderr, "Dropping priviledges to uid=%d gid=%d\n", drop_uid, drop_gid);
      if ( setgid(drop_gid) != 0 ){
	logmsg(stderr, "setgid() failed: %s\n", strerror(errno));
      }
      if ( setuid(drop_uid) != 0 ){
	logmsg(stderr, "setuid() failed: %s\n", strerror(errno));
      }
    } else {
      logmsg(stderr, "Not executing as uid=0, cannot drop priviledges.\n");
    }
  }

  /* wait for events */
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
      logmsg(stderr, "marc_poll_event() returned %d: %s\n", ret, strerror(ret));
      return 1;
    }

    if ( debug_flag ){
      logmsg(verbose, "Received event of type %d (%zd bytes)\n", event.type, bytes);
      hexdump(verbose, (const char*)&event, bytes);
    }

    switch ( event.type ){
    case MP_CONTROL_INIT_EVENT:
      MP_Init(marc, &event.init, &from);
      break;
    
    case MP_STATUS_EVENT:
      MP_Status(marc, &event.status, &from);
      break;

    case MP_STATUS2_EVENT:
      MP_Status2(marc, &event.status2, &from);
      break;

    case MP_FILTER_REQUEST_EVENT:
      MP_GetFilter(marc, &event.filter_id, &from);
      break;

    case MP_CONTROL_DISTRESS:
      MP_Distress(marc, mampid_get(event.MAMPid), &from);
      break;

    default:
      logmsg(stderr, "not handling message of type %d\n", event.type);
    }
  }

  free(rrdpath);

  return 0;
}

static int connect(){
  logmsg(verbose, "Connecting to mysql://%s@%s:%d/%s (using password: %s)\n",
	 db_username, db_hostname, db_port, db_name, db_password[0] != 0 ? "YES" : "NO");
  if ( !mysql_real_connect(&connection, db_hostname, db_username, db_password, db_name,db_port,0,0) ){
    logmsg(stderr, "Failed to connect to database: %s\n", mysql_error(&connection));
    return 0;
  }
  return 1;
}


/**
 * Fetches a row from the MySQL resultset, parses it and sends it as a packed filter to dst
 * @return Zero on error.
 */
static int send_mysql_filter(marc_context_t marc, MYSQL_RES *result, struct sockaddr* dst, const char* MAMPid){
  struct FPI fpi;
  struct MPFilter MPfilter;
  
  if ( !convMySQLtoFPI(&fpi, result) ){
    return 0;
  }

  struct Filter* filter = &fpi.filter;
  
  MPfilter.type = MP_FILTER_EVENT;
  mampid_set(MPfilter.MAMPid, MAMPid);
  marc_filter_pack(filter, &MPfilter.filter);
  
  logmsg(verbose, "Sending Filter {%d} to to MP %s.\n", filter->filter_id, mampid_get(MPfilter.MAMPid));

  if ( debug_flag ){
    hexdump(verbose, (char*)&MPfilter, sizeof(struct MPFilter));
  }
  
  int ret;
  if ( (ret=marc_push_event(marc, (MPMessage*)&MPfilter, dst)) != 0 ){
    logmsg(stderr, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
    return 0;
  }

  return 1;
}

static int q(const char* sql, ...){
  char query[2000] = {0,};

  va_list ap;
  va_start(ap, sql);
  vsnprintf(query, sizeof(query), sql, ap);
  va_end(ap);

  if ( mysql_ping(&connection) != 0 ){
    logmsg(stderr, "Connection to MySQL lost: %s\n", mysql_error(&connection));
    logmsg(stderr, "Trying to reconnect.\n");
    if ( !connect() ){
      return 0;
    }
  }

  if ( debug_flag ){
    logmsg(verbose, "Executing SQL query:\n%s\n", query);
  }

  if ( mysql_query(&connection,query) != 0 ) {
    logmsg(stderr, "Failed to execute MySQL query: %s\nThe query was: %s\n", mysql_error(&connection), query);
    return 0;
  }

  return 1;
}

static void MP_Init(marc_context_t marc, MPinitialization* MPinit, struct sockaddr* from){
  struct sockaddr_in MPadr;
  struct MPauth MPauth;
  int ret;

  MPauth.type = MP_CONTROL_AUTHORIZE_EVENT;
  mampid_set(MPauth.MAMPid, 0);
  MPauth.version.major = htons(LIBMARC_VERSION_MAJOR);
  MPauth.version.minor = htons(LIBMARC_VERSION_MINOR);

  memcpy(&MPadr.sin_addr.s_addr, MPinit->ipaddress,sizeof(struct in_addr));

  logmsg(verbose, "MPinitialization:\n", inet_ntoa(MPadr.sin_addr), ntohs(MPinit->port));
  logmsg(verbose, "      .type= %d \n",MPinit->type);
  logmsg(verbose, "      .mac = %s \n", hexdump_address(&MPinit->hwaddr));
  logmsg(verbose, "      .name= %s \n",MPinit->hostname);
  logmsg(verbose, "      .ipaddress = %s \n", inet_ntoa(MPadr.sin_addr));
  logmsg(verbose, "      .port = %d \n", ntohs(MPinit->port));
  logmsg(verbose, "      .maxFilters = %d \n",ntohs(MPinit->maxFilters));
  logmsg(verbose, "      .noCI = %d \n", ntohs(MPinit->noCI));
  logmsg(verbose, "      .MAMPid = %s \n", mampid_get(MPinit->MAMPid));

  if ( ntohs(MPinit->version.protocol.major) > 0 || ntohs(MPinit->version.protocol.minor) >= 7 ){
    logmsg(verbose, "      .version.protocol = %d.%d\n", ntohs(MPinit->version.protocol.major), ntohs(MPinit->version.protocol.minor));
    logmsg(verbose, "      .version.caputils = %d.%d.%d\n", MPinit->version.caputils.major, MPinit->version.caputils.minor , MPinit->version.caputils.micro);
    logmsg(verbose, "      .version.libmarc  = %d.%d.%d\n", MPinit->version.libmarc.major, MPinit->version.libmarc.minor , MPinit->version.libmarc.micro);
    logmsg(verbose, "      .version.mp       = %d.%d.%d\n", MPinit->version.self.major, MPinit->version.self.minor , MPinit->version.self.micro);
    logmsg(verbose, "      .drivers          = %d\n", ntohl(MPinit->drivers));

    for ( int i = 0; i < ntohs(MPinit->noCI); i++ ){
      logmsg(verbose, "      .CI[%d].iface      = %.8s\n", i, MPinit->CI[i].iface);
    }
  }
  
  if ( !q("SELECT MAMPid FROM measurementpoints WHERE mac='%s' AND name='%s'", hexdump_address(&MPinit->hwaddr), MPinit->hostname) ){
    return;
  }

  char MAMPid[16] = {0,};
  
  MYSQL_RES* result = mysql_store_result(&connection);
  if(mysql_num_rows(result)==0){ /* We are a new MP..  */
    logmsg(verbose, "This is an unregisterd MP.\n");
    mysql_free_result(result);

    if ( !q("INSERT INTO measurementpoints SET name='%s',ip='%s',port='%d',mac='%s',maxFilters=%d,noCI=%d"
	    ,MPinit->hostname
	    ,inet_ntoa(MPadr.sin_addr)
	    ,ntohs(MPinit->port)
	    ,hexdump_address(&MPinit->hwaddr)
	    ,ntohs(MPinit->maxFilters)
	    ,ntohs(MPinit->noCI)) ){
      return;
    }
  } else { /* known MP */
    MYSQL_ROW row = mysql_fetch_row(result);
    strncpy(MAMPid, row[0], 16);
    mysql_free_result(result);
  }

  logmsg(verbose, "MAMPid = %s (%zd) \n", MAMPid, strlen(MAMPid));
  mampid_set(MPauth.MAMPid, MAMPid);

  if ( debug_flag ){
    logmsg(verbose, "Sending authorization reply.\n");
    hexdump(verbose, (const char*)&MPauth, sizeof(struct MPauth));
  }

  /* Send authorize message (telling whenever it is authorized or not) */
  if ( (ret=marc_push_event(marc, (MPMessage*)&MPauth, from)) != 0 ){
    logmsg(stderr, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
    return;
  }

  if( strlen(MAMPid) == 0){ // The MP exists, but isnt authorized.
    if ( !verbose_flag ){
      logmsg(stderr, "MPinitialization request from %s:%d -> not authorized\n", inet_ntoa(MPadr.sin_addr), ntohs(MPinit->port));
    } else {
      logmsg(verbose, "This MP exists but is not yet authorized.\n");
    }
    return;
  } else if (!verbose_flag){
    logmsg(stderr, "MPinitialization request from %s:%d -> authorized\n", inet_ntoa(MPadr.sin_addr), ntohs(MPinit->port));
  }

  /* reset status counters */
  MP_Status2_reset(MAMPid, ntohs(MPinit->noCI));

  /* register that the MP now is idle (doesn't really matter as heurestics is used for status, but it clears the distress state) */
  mp_set_status(MAMPid, MP_STATUS_IDLE);

  /* Lets check if we have any filters waiting for us? */
  if ( !q("SELECT * from %s_filterlist ORDER BY 'filter_id' ASC ",MAMPid) ){
    return;
  }

  result = mysql_store_result(&connection);
  int rows = (int)mysql_num_rows(result);
  logmsg(verbose, "MP %s has %d filters assigned.\n", MAMPid, rows);
  
  /*process each row*/  
  for( int n=0; n < rows; n++ ){
    send_mysql_filter(marc, result, from, MAMPid);
  }

  /* free the result set */
  mysql_free_result(result);

  logmsg(verbose, "MP_init done.\n");
  return;
}

static void MP_Status(marc_context_t marc, MPstatus* MPstat, struct sockaddr* from){
  LOG_EVENT("MPstatus", mampid_get(MPstat->MAMPid));
  
  if ( MPstat->MAMPid[0] == 0 ){
    logmsg(stderr, "MPstat with invalid MAMPid (null)\n");
    return;
  }

  /* bump timestamp */ {
    char buf[16*2+1]; /* mampids are 16 bytes, worst-case escape requires n*2 chars + nullterminator */
    mysql_real_escape_string(&connection, buf, mampid_get(MPstat->MAMPid), strlen(MPstat->MAMPid));
    q("UPDATE measurementpoints SET time = CURRENT_TIMESTAMP WHERE MAMPid = '%s'", buf);
  }

  q("INSERT INTO %s_CIload SET noFilters='%d', matchedPkts='%d' %s",
    mampid_get(MPstat->MAMPid), ntohl(MPstat->noFilters), ntohl(MPstat->matched), MPstat->CIstats);
}

static void MP_GetFilter(marc_context_t marc, MPFilterID* filter, struct sockaddr* from){
  LOG_EVENT("MPFilterID", mampid_get(filter->MAMPid));

  if ( filter->MAMPid[0] == 0 ){
    logmsg(stderr, "MPFilterID with invalid MAMPid (null)\n");
    return;
  }

  if ( !q("SELECT * FROM %s_filterlist WHERE filter_id='%d' LIMIT 1",
	  mampid_get(filter->MAMPid), ntohl(filter->id)) ){
    return;
  }

  MYSQL_RES* result = mysql_store_result(&connection);
  if ( !send_mysql_filter(marc, result, from, filter->MAMPid) ){
    logmsg(verbose, "No filter matching {%02d}\n", ntohl(filter->id));
    MPMessage reply;
    reply.type = MP_FILTER_INVALID_ID;
    int ret;
    if ( (ret=marc_push_event(marc, &reply, from)) != 0 ){
      logmsg(stderr, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
    }
  }
  mysql_free_result(result);
}

static void MP_VerifyFilter(int sd, struct sockaddr from, char *buffer){
  char statusQ[2000];
  static char buf[100];
  char *query;
  query=statusQ;
  bzero(statusQ,sizeof(statusQ));
  struct MPVerifyFilter* MyVerify=(struct MPVerifyFilter*)buffer;
  struct FilterPacked* F = &MyVerify->filter;
  if(MyVerify->flags==0) {
    sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', comment='NOT PRESENT'", MyVerify->MAMPid,MyVerify->filter_id); 
  } else {
    sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', ind='%d', CI_ID='%s', VLAN_TCI='%d', VLAN_TCI_MASK='%d',ETH_TYPE='%d', ETH_TYPE_MASK='%d',ETH_SRC='%s',ETH_SRC_MASK='%s', ETH_DST='%s', ETH_DST_MASK='%s',IP_PROTO='%d', IP_SRC='%s', IP_SRC_MASK='%s', IP_DST='%s', IP_DST_MASK='%s', SRC_PORT='%d', SRC_PORT_MASK='%d', DST_PORT='%d', DST_PORT_MASK='%d', TYPE='%d', CAPLEN='%d', consumer='%d'",
	    MyVerify->MAMPid,F->filter_id,F->index,F->CI_ID,F->VLAN_TCI,F->VLAN_TCI_MASK,
	    F->ETH_TYPE,F->ETH_TYPE_MASK,
	    hexdump_address_r(&F->ETH_SRC, &buf[0]), hexdump_address_r(&F->ETH_SRC_MASK, &buf[17]),
	    hexdump_address_r(&F->ETH_DST, &buf[0]), hexdump_address_r(&F->ETH_DST_MASK, &buf[17]),
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
  if ( mysql_query(&connection, query) != 0 ) {
    logmsg(stderr, "Failed to execute mysql query: %s\nThe query was: %s\n", mysql_error(&connection), query);
    return;
  }

  return;
}

static void MP_Distress(marc_context_t marc, const char* mampid, struct sockaddr* from){
  logmsg(stderr, "Distress signal from MP (MAMPid: %s)\n", mampid);
  mp_set_status(mampid, MP_STATUS_DISTRESS);
}

static int convMySQLtoFPI(struct FPI *fpi,  MYSQL_RES *result){
  struct Filter* rule = &fpi->filter;

  char *pos=0;
  MYSQL_ROW row = mysql_fetch_row(result);

  if ( !row ){ /* no more rows */
    return 0;
  }

  rule->filter_id=atoi(row[0]);
  rule->index=atoi(row[1]);
  strncpy(rule->CI_ID,row[2],8);
  rule->VLAN_TCI=atol(row[3]);
  rule->VLAN_TCI_MASK=atol(row[4]);
  rule->ETH_TYPE=atol(row[5]);
  rule->ETH_TYPE_MASK=atol(row[6]);
  
  
  rule->IP_PROTO=atoi(row[11]);
  strncpy((char*)rule->IP_SRC,row[12],16);
  strncpy((char*)rule->IP_SRC_MASK,row[13],16);
  strncpy((char*)rule->IP_DST,row[14],16);
  strncpy((char*)rule->IP_DST_MASK,row[15],16);
  
  rule->SRC_PORT=atoi(row[16]);
  rule->SRC_PORT_MASK=atoi(row[17]);
  rule->DST_PORT=atoi(row[18]);
  rule->DST_PORT_MASK=atoi(row[19]);
  rule->consumer=atoi(row[20]);
  
  inet_atoP((char*)rule->ETH_SRC.ether_addr_octet,row[7]);
  inet_atoP((char*)rule->ETH_SRC_MASK.ether_addr_octet,row[8]);
  inet_atoP((char*)rule->ETH_DST.ether_addr_octet,row[9]);
  inet_atoP((char*)rule->ETH_DST_MASK.ether_addr_octet,row[10]);

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
static int inet_atoP(char *dest,char *org){
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

static void mp_set_status(const char* mampid, enum MPStatusEnum status){
  char buf[16*2+1]; /* mampids are 16 bytes, worst-case escape requires n*2 chars + nullterminator */
  mysql_real_escape_string(&connection, buf, mampid, strlen(mampid));
  q("UPDATE measurementpoints SET status = %d WHERE MAMPid = '%s'", status, buf);
}
