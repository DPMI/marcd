#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define LOG_EVENT(x, mampid)							\
  logmsg(verbose, x " from %s:%d (MAMPid: %s)\n", \
  inet_ntoa(((struct sockaddr_in*)from)->sin_addr), ntohs(((struct sockaddr_in*)from)->sin_port), mampid)

#include "database.h"
#include "utils.h"

#include <libmarc/libmarc.h>
#include <libmarc/log.h>
#include <libmarc/version.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

enum MPStatusEnum {
  MP_STATUS_NOT_AUTH,
  MP_STATUS_IDLE,
  MP_STATUS_CAPTURE,
  MP_STATUS_STOPPED,
  MP_STATUS_DISTRESS,
};

extern int verbose_flag;
extern int debug_flag;
extern FILE* verbose;

extern int ma_control_port;
static marc_context_t marc;

static void MP_Init(marc_context_t marc, MPinitialization* init, struct sockaddr* from);
static void MP_Status(marc_context_t marc, MPstatus* MPstat, struct sockaddr* from);
static void MP_GetFilter(marc_context_t marc, MPFilterID* filter, struct sockaddr* from);
static void MP_VerifyFilter(int sd, struct sockaddr from, char buffer[1500]);
static void MP_Distress(marc_context_t marc, const char* mampid, struct sockaddr* from);
static void mp_set_status(const char* mampid, enum MPStatusEnum status);
void MP_Status2_reset(const char* MAMPid, int noCI);
void MP_Status2(marc_context_t marc, MPstatus2* MPstat, struct sockaddr* from);

static int convMySQLtoFPI(struct filter* dst,  MYSQL_RES* src);

int ma_control_init(){
  /* redirect output */
  marc_set_output_handler(logmsg, vlogmsg, stderr, verbose);

  /* initialize mysql */
  mysql_init(&connection);
  if ( !db_connect() ){
    return 1;
  }

  /* initialize libmarc */
  int ret;
  if ( (ret=marc_init_server(&marc, ma_control_port)) != 0 ){
    logmsg(stderr, "marc_init_server() returned %d: %s\n", ret, strerror(ret));
    return 1;
  }

  return 0;
}

int ma_control_cleanup(){
  return 0;
}

int ma_control_run(){
  int ret;

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

  return 0;
}

static int convMySQLtoFPI(struct filter* rule,  MYSQL_RES* result){
  MYSQL_ROW row = mysql_fetch_row(result);

  if ( !row ){ /* no more rows */
    return 0;
  }

  rule->filter_id=atoi(row[0]);
  rule->index=atoi(row[1]);
  strncpy(rule->iface, row[2], 8);
  rule->vlan_tci=atol(row[3]);
  rule->vlan_tci_mask=atol(row[4]);
  rule->eth_type=atol(row[5]);
  rule->eth_type_mask=atol(row[6]);
  
  
  rule->ip_proto=atoi(row[11]);
  rule->ip_src.s_addr = inet_addr(row[12]);
  rule->ip_src_mask.s_addr = inet_addr(row[13]);
  rule->ip_dst.s_addr = inet_addr(row[14]);
  rule->ip_dst_mask.s_addr = inet_addr(row[15]);
  
  rule->src_port=atoi(row[16]);
  rule->src_port_mask=atoi(row[17]);
  rule->dst_port=atoi(row[18]);
  rule->dst_port_mask=atoi(row[19]);
  rule->consumer=atoi(row[20]);
  
  inet_atoP((char*)rule->eth_src.ether_addr_octet,row[7]);
  inet_atoP((char*)rule->eth_src_mask.ether_addr_octet,row[8]);
  inet_atoP((char*)rule->eth_dst.ether_addr_octet,row[9]);
  inet_atoP((char*)rule->eth_dst_mask.ether_addr_octet,row[10]);

  rule->caplen=atoi(row[23]);

  const char* destination = row[21];
  enum DestinationType type = (enum DestinationType)atoi(row[22]);
  destination_aton(&rule->dest, destination, type, 0);

  return 1;
}

/**
 * Fetches a row from the MySQL resultset, parses it and sends it as a packed filter to dst
 * @return Zero on error.
 */
static int send_mysql_filter(marc_context_t marc, MYSQL_RES *result, struct sockaddr* dst, const char* MAMPid){
  struct MPFilter MPfilter;
  struct filter filter;

  if ( !convMySQLtoFPI(&filter, result) ){
    return 0;
  }
  
  MPfilter.type = MP_FILTER_EVENT;
  mampid_set(MPfilter.MAMPid, MAMPid);
  marc_filter_pack(&filter, &MPfilter.filter);
  
  logmsg(verbose, "Sending Filter {%d} to to MP %s.\n", filter.filter_id, mampid_get(MPfilter.MAMPid));

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
  
  if ( !db_query("SELECT MAMPid FROM measurementpoints WHERE mac='%s' AND name='%s'", hexdump_address(&MPinit->hwaddr), MPinit->hostname) ){
    return;
  }

  char MAMPid[16] = {0,};
  
  MYSQL_RES* result = mysql_store_result(&connection);
  if(mysql_num_rows(result)==0){ /* We are a new MP..  */
    logmsg(verbose, "This is an unregisterd MP.\n");
    mysql_free_result(result);

    if ( !db_query("INSERT INTO measurementpoints SET name='%s',ip='%s',port='%d',mac='%s',maxFilters=%d,noCI=%d"
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
  if ( !db_query("SELECT * FROM `%s_filterlist` ORDER BY `filter_id` ASC", MAMPid) ){
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
    db_query("UPDATE measurementpoints SET time = CURRENT_TIMESTAMP WHERE MAMPid = '%s'", buf);
  }

  db_query("INSERT INTO %s_CIload SET noFilters='%d', matchedPkts='%d' %s",
    mampid_get(MPstat->MAMPid), ntohl(MPstat->noFilters), ntohl(MPstat->matched), MPstat->CIstats);
}

static void MP_GetFilter(marc_context_t marc, MPFilterID* filter, struct sockaddr* from){
  LOG_EVENT("MPFilterID", mampid_get(filter->MAMPid));

  if ( filter->MAMPid[0] == 0 ){
    logmsg(stderr, "MPFilterID with invalid MAMPid (null)\n");
    return;
  }

  if ( !db_query("SELECT * FROM %s_filterlist WHERE filter_id='%d' LIMIT 1",
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
  static char buf[200];
  char *query;
  query=statusQ;
  bzero(statusQ,sizeof(statusQ));
  struct MPVerifyFilter* MyVerify=(struct MPVerifyFilter*)buffer;
  struct filter_packed* f = &MyVerify->filter;
  if(MyVerify->flags==0) {
    sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', comment='NOT PRESENT'", MyVerify->MAMPid,MyVerify->filter_id); 
  } else {
    sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', ind='%d', CI_ID='%s', VLAN_TCI='%d', VLAN_TCI_MASK='%d',ETH_TYPE='%d', ETH_TYPE_MASK='%d',ETH_SRC='%s',ETH_SRC_MASK='%s', ETH_DST='%s', ETH_DST_MASK='%s',IP_PROTO='%d', IP_SRC='%s', IP_SRC_MASK='%s', IP_DST='%s', IP_DST_MASK='%s', SRC_PORT='%d', SRC_PORT_MASK='%d', DST_PORT='%d', DST_PORT_MASK='%d', TYPE='%d', CAPLEN='%d', consumer='%d'",
	    MyVerify->MAMPid, f->filter_id, f->index, f->iface, f->vlan_tci, f->vlan_tci_mask,
	    f->eth_type,f->eth_type_mask,
	    hexdump_address_r(&f->eth_src, &buf[0]), hexdump_address_r(&f->eth_src_mask, &buf[17]),
	    hexdump_address_r(&f->eth_dst, &buf[34]), hexdump_address_r(&f->eth_dst_mask, &buf[51]),
	    f->ip_proto,
	    inet_ntoa_r(f->ip_src, &buf[ 68]), inet_ntoa_r(f->ip_src_mask, &buf[ 85]),
	    inet_ntoa_r(f->ip_dst, &buf[102]), inet_ntoa_r(f->ip_dst_mask, &buf[119]),
	    f->src_port,f->src_port_mask,f->dst_port,f->dst_port_mask,
	    f->dest.type, 
	    f->caplen,
	    f->consumer);
      
    sprintf(query, "%s, DESTADDR='%s' ", query, destination_ntoa(&f->dest));
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

static void mp_set_status(const char* mampid, enum MPStatusEnum status){
  char buf[16*2+1]; /* mampids are 16 bytes, worst-case escape requires n*2 chars + nullterminator */
  mysql_real_escape_string(&connection, buf, mampid, strlen(mampid));
  db_query("UPDATE measurementpoints SET status = %d WHERE MAMPid = '%s'", status, buf);
}
