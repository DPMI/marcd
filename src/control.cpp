#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "control.hpp"
#include "database.hpp"
#include "utils.hpp"
#include "log.hpp"

#define LOG_EVENT(x, mampid)							\
	Log::verbose("control", x " from %s:%d (MAMPid: %s)\n", \
  inet_ntoa(((struct sockaddr_in*)from)->sin_addr), ntohs(((struct sockaddr_in*)from)->sin_port), mampid)

#include <caputils/marc.h>
#include <caputils/log.h>
#include <caputils/utils.h>
#include <caputils/version.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

enum MPStatusEnum {
	MP_STATUS_NOT_AUTH,        /* MP not yet authorized by MArCd */
	MP_STATUS_IDLE,            /* Authorized, running but have no filter */
	MP_STATUS_CAPTURE,         /* Authorized, running and have filters */
	MP_STATUS_STOPPED,         /* Authorized but isn't running */
	MP_STATUS_DISTRESS,        /* MP crashed (e.g. SIGSEGV) */
	MP_STATUS_TERMINATED,      /* MP was terminated by remote */
	MP_STATUS_TIMEOUT,         /* MP has not been heard from for a long period of time */
};

extern int verbose_flag;
extern int debug_flag;
extern bool volatile keep_running;

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
void setup_rrd_tables(const char* mampid, unsigned int noCI, const char* iface[]);

static int convMySQLtoFPI(struct filter* dst,  MYSQL_RES* src);

int Control::init(){
	/* initialize mysql */
	mysql_init(&connection);
	if ( !db_connect() ){
		return 1;
	}

	/* initialize libmarc */
	int ret;
	if ( (ret=marc_init_server(&marc, ma_control_port)) != 0 ){
		Log::fatal("MArCd", "marc_init_server() returned %d: %s\n", ret, strerror(ret));
		return 1;
	}

	return 0;
}

int Control::cleanup(){
	Log::verbose("MArCd", "Thread finished.\n");
	return 0;
}

int Control::run(){
	int ret;

	/* wait for events */
	while ( keep_running ){
		MPMessage event;
		struct sockaddr_in from;
		socklen_t addrlen = sizeof(struct sockaddr_in);
		struct timeval timeout = {1, 0}; /* 1 sec timeout */
		size_t bytes;
		switch ( (ret=marc_poll_event(marc, &event, &bytes, (struct sockaddr*)&from, &addrlen, &timeout)) ){
		case EAGAIN: /* delivered if using a timeout */
		case EINTR:  /* interuped */
			continue;

		case 0:
			break;

		default:
			Log::fatal("MArCd", "marc_poll_event() returned %d: %s\n", ret, strerror(ret));
			return 1;
		}

		if ( debug_flag ){
			char* repr = hexdump_str((const char*)&event, bytes);
			Log::debug("MArCd", "Received event of type %d (%zd bytes):\n%s", event.type, bytes, repr);
			free(repr);
		}

		switch ( event.type ){
		case MP_CONTROL_INIT_EVENT:
			MP_Init(marc, &event.init, (struct sockaddr*)&from);
			break;

		case MP_STATUS_EVENT:
			MP_Status(marc, &event.status, (struct sockaddr*)&from);
			break;

		case MP_STATUS2_EVENT:
			MP_Status2(marc, &event.status2, (struct sockaddr*)&from);
			break;

		case MP_FILTER_REQUEST_EVENT:
			MP_GetFilter(marc, &event.filter_id, (struct sockaddr*)&from);
			break;

		case MP_CONTROL_TERMINATE_EVENT:
			Log::verbose("MArCd", "MP %s has terminated properly.\n", mampid_get(event.MAMPid));
			mp_set_status(mampid_get(event.MAMPid), MP_STATUS_TERMINATED);
			break;

		case MP_CONTROL_DISTRESS:
			MP_Distress(marc, mampid_get(event.MAMPid), (struct sockaddr*)&from);
			break;

		default:
			Log::fatal("MArCd", "not handling message of type %d\n", event.type);
		}
	}

	return 0;
}

static int convMySQLtoFPI(struct filter* rule,  MYSQL_RES* result){
	MYSQL_ROW row = mysql_fetch_row(result);

	if ( !row ){ /* no more rows */
		return 0;
	}

	/* filter_id, index, mode, CI, VLAN_TCI, VLAN_TCI_MASK, ETH_TYPE, ETH_TYPE_MASK, ETH_SRC, ETH_SRC_MASK, ETH_DST, ETH_DST_MASK, IP_PROTO, IP_SRC, IP_SRC_MASK, IP_DST, IP_DST_MASK, SRC_PORT, SRC_PORT_MASK, DST_PORT, DST_PORT_MASK, DESTADDR, TYPE, CAPLEN */

	/* base fields */
	rule->filter_id = atoi(row[0]);
	rule->index = atoi(row[1]);
	rule->mode = (FilterMode)atoi(row[2]);
	rule->consumer = atoi(row[21]);
	rule->caplen = atoi(row[24]);

	strncpy(rule->iface, row[3], 8);
	rule->vlan_tci=atol(row[4]);
	rule->vlan_tci_mask=atol(row[5]);
	rule->eth_type=atol(row[6]);
	rule->eth_type_mask=atol(row[7]);

	inet_atoP((char*)rule->eth_src.ether_addr_octet,row[8]);
	inet_atoP((char*)rule->eth_src_mask.ether_addr_octet,row[9]);
	inet_atoP((char*)rule->eth_dst.ether_addr_octet,row[10]);
	inet_atoP((char*)rule->eth_dst_mask.ether_addr_octet,row[11]);

	rule->ip_proto=atoi(row[12]);
	rule->ip_src.s_addr = inet_addr(row[13]);
	rule->ip_src_mask.s_addr = inet_addr(row[14]);
	rule->ip_dst.s_addr = inet_addr(row[15]);
	rule->ip_dst_mask.s_addr = inet_addr(row[16]);

	rule->src_port=atoi(row[17]);
	rule->src_port_mask=atoi(row[18]);
	rule->dst_port=atoi(row[19]);
	rule->dst_port_mask=atoi(row[20]);

	/* destination */
	const char* destination = row[21];
	enum AddressType type = (enum AddressType)atoi(row[22]);
	stream_addr_aton(&rule->dest, destination, type, 0);

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
	filter_pack(&filter, &MPfilter.filter);

	Log::verbose("MArCd", "Sending Filter {%d} to to MP %s.\n", filter.filter_id, mampid_get(MPfilter.MAMPid));

	if ( debug_flag ){
		char* repr = hexdump_str((char*)&MPfilter, sizeof(struct MPFilter));
		Log::debug("MArcd", "%s", repr);
		free(repr);
	}

	int ret;
	if ( (ret=marc_push_event(marc, (MPMessage*)&MPfilter, dst)) != 0 ){
		Log::fatal("MArCd", "marc_push_event() returned %d: %s\n", ret, strerror(ret));
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
	MPauth.version.major = htons(CAPUTILS_VERSION_MAJOR);
	MPauth.version.minor = htons(CAPUTILS_VERSION_MINOR);

	memcpy(&MPadr.sin_addr.s_addr, MPinit->ipaddress,sizeof(struct in_addr));

	Log::verbose("MArCd", "MPinitialization from %s:%d:\n", inet_ntoa(MPadr.sin_addr), ntohs(MPinit->port));
	Log::verbose("MArCd", "     .type= %d \n",MPinit->type);
	Log::verbose("MArCd", "     .mac = %s \n", hexdump_address(&MPinit->hwaddr));
	Log::verbose("MArCd", "     .name= %s \n",MPinit->hostname);
	Log::verbose("MArCd", "     .ipaddress = %s \n", inet_ntoa(MPadr.sin_addr));
	Log::verbose("MArCd", "     .port = %d \n", ntohs(MPinit->port));
	Log::verbose("MArCd", "     .maxFilters = %d \n",ntohs(MPinit->maxFilters));
	Log::verbose("MArCd", "     .noCI = %d \n", ntohs(MPinit->noCI));
	Log::verbose("MArCd", "     .MAMPid = %s \n", mampid_get(MPinit->MAMPid));

	if ( ntohs(MPinit->version.protocol.major) > 0 || ntohs(MPinit->version.protocol.minor) >= 7 ){
		Log::verbose("MArCd", "     .version.protocol = %d.%d\n", ntohs(MPinit->version.protocol.major), ntohs(MPinit->version.protocol.minor));
		Log::verbose("MArCd", "     .version.caputils = %d.%d.%d\n", MPinit->version.caputils.major, MPinit->version.caputils.minor , MPinit->version.caputils.micro);
		Log::verbose("MArCd", "     .version.mp       = %d.%d.%d\n", MPinit->version.self.major, MPinit->version.self.minor , MPinit->version.self.micro);
		Log::verbose("MArCd", "     .drivers          = %d\n", ntohl(MPinit->drivers));

		for ( int i = 0; i < ntohs(MPinit->noCI); i++ ){
			Log::verbose("MArCd", "     .CI[%d].iface      = %.8s\n", i, MPinit->CI[i].iface);
		}
	}

	if ( !db_query("SELECT `id`, `MAMPid` FROM `measurementpoints` WHERE mac='%s' AND name='%s'", hexdump_address(&MPinit->hwaddr), MPinit->hostname) ){
		return;
	}

	int id;
	char MAMPid[16] = {0,};

	MYSQL_RES* result = mysql_store_result(&connection);
	if(mysql_num_rows(result)==0){ /* We are a new MP..  */
		Log::verbose("MArCd", "This is an unregisterd MP.\n");
		mysql_free_result(result);

		if ( !db_query("INSERT INTO\n"
		               "  measurementpoints\n"
		               "SET\n"
		               "  name='%s',\n"
		               "  ip='%s',\n"
		               "  port='%d',\n"
		               "  mac='%s',\n"
		               "  maxFilters=%d,\n"
		               "  noCI=%d\n"
		               , MPinit->hostname
		               , inet_ntoa(MPadr.sin_addr)
		               , ntohs(MPinit->port)
		               , hexdump_address(&MPinit->hwaddr)
		               , ntohs(MPinit->maxFilters)
		               , ntohs(MPinit->noCI)) ){
			return;
		}
	} else { /* known MP */
		MYSQL_ROW row = mysql_fetch_row(result);
		id = atoi(row[0]);
		strncpy(MAMPid, row[1], 16);
		mysql_free_result(result);
	}

	/* update fields every time the mp initializes (0.7 feature) */
	if ( ntohs(MPinit->version.protocol.major) > 0 || ntohs(MPinit->version.protocol.minor) >= 7 ){
		char version[256];
		char iface[256];
		snprintf(version, 256, "protocol-%d.%d;caputils-%d.%d.%d;mp-%d.%d.%d",
		         ntohs(MPinit->version.protocol.major), ntohs(MPinit->version.protocol.minor),
		         MPinit->version.caputils.major, MPinit->version.caputils.minor , MPinit->version.caputils.micro,
		         MPinit->version.self.major, MPinit->version.self.minor , MPinit->version.self.micro);


		int offset = 0;
		for ( int i = 0; i < ntohs(MPinit->noCI); i++ ){
			offset += snprintf(iface+offset, 256-offset, "%s;", MPinit->CI[i].iface);
		}
		iface[offset-1] = '\0'; /* remove trailing ; */

		db_query("UPDATE\n"
		         "  measurementpoints\n"
		         "SET\n"
		         "  ip='%s',\n"
		         "  port='%d',\n"
		         "  maxFilters=%d,\n"
		         "  drivers=%d,\n"
		         "  version='%s',\n"
		         "  CI_iface='%s'\n"
		         "WHERE\n"
		         "  mampid='%s'"
		         , inet_ntoa(MPadr.sin_addr)
		         , ntohs(MPinit->port)
		         , ntohs(MPinit->maxFilters)
		         , ntohl(MPinit->drivers),
		         version, iface,
		         MAMPid);
	}

	Log::verbose("MArCd", "MAMPid = %s (%zd) \n", MAMPid, strlen(MAMPid));
	mampid_set(MPauth.MAMPid, MAMPid);
	int is_authorized = strlen(MAMPid) > 0;

	if ( debug_flag ){
		char* repr = hexdump_str((const char*)&MPauth, sizeof(struct MPauth));
		Log::debug("MArCd", "Sending authorization reply.\n%s", repr);
		free(repr);
	}

	/* Send authorize message (telling whenever it is authorized or not) */
	if ( (ret=marc_push_event(marc, (MPMessage*)&MPauth, from)) != 0 ){
		Log::fatal("MArCd", "marc_push_event() returned %d: %s\n", ret, strerror(ret));
		return;
	}

	if( !is_authorized ){ // The MP exists, but isnt authorized.
		if ( !verbose_flag ){
			Log::fatal("MArCd", "MPinitialization request from %s:%d -> not authorized\n", inet_ntoa(MPadr.sin_addr), ntohs(MPinit->port));
		} else {
			Log::verbose("MArCd", "This MP exists but is not yet authorized.\n");
		}
		return;
	} else if (!verbose_flag){
		Log::fatal("MArCd", "MPinitialization request from %s:%d -> authorized\n", inet_ntoa(MPadr.sin_addr), ntohs(MPinit->port));
	}

	/* setup RRD tables as needed */
	if ( is_authorized ){
		const char* iface[MPinit->noCI];
		for (int i=0; i < MPinit->noCI; i++ ){
			iface[i] = MPinit->CI[i].iface;
		}
		setup_rrd_tables(mampid_get(MPauth.MAMPid), ntohs(MPinit->noCI), iface);
	}

	/* register that the MP now is idle (doesn't really matter as heurestics is used for status, but it clears the distress state) */
	mp_set_status(MAMPid, MP_STATUS_IDLE);

	/* Lets check if we have any filters waiting for us? */
	if ( !db_query("SELECT filter_id, `index`, mode+0, CI, VLAN_TCI, VLAN_TCI_MASK, ETH_TYPE, ETH_TYPE_MASK, ETH_SRC, ETH_SRC_MASK, ETH_DST, ETH_DST_MASK, IP_PROTO, IP_SRC, IP_SRC_MASK, IP_DST, IP_DST_MASK, SRC_PORT, SRC_PORT_MASK, DST_PORT, DST_PORT_MASK, destaddr, type, caplen FROM `filter` WHERE `mp` = %d ORDER BY `filter_id` ASC", id) ){
		return;
	}

	result = mysql_store_result(&connection);
	int rows = (int)mysql_num_rows(result);
	Log::verbose("MArCd", "MP %s has %d filters assigned.\n", MAMPid, rows);

	/*process each row*/
	for( int n=0; n < rows; n++ ){
		send_mysql_filter(marc, result, from, MAMPid);
	}

	/* free the result set */
	mysql_free_result(result);

	Log::verbose("MArCd", "MP_init done.\n");
	return;
}

static void MP_Status(marc_context_t marc, MPstatus* MPstat, struct sockaddr* from){
	LOG_EVENT("MPstatus", mampid_get(MPstat->MAMPid));

	if ( MPstat->MAMPid[0] == 0 ){
		Log::fatal("MArCd", "MPstat with invalid MAMPid (null)\n");
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
		Log::fatal("MArCd", "MPFilterID with invalid MAMPid (null)\n");
		return;
	}

	if ( !db_query("SELECT filter_id, `index`, mode+0, CI, VLAN_TCI, VLAN_TCI_MASK, ETH_TYPE, ETH_TYPE_MASK, ETH_SRC, ETH_SRC_MASK, ETH_DST, ETH_DST_MASK, IP_PROTO, IP_SRC, IP_SRC_MASK, IP_DST, IP_DST_MASK, SRC_PORT, SRC_PORT_MASK, DST_PORT, DST_PORT_MASK, destaddr, type, caplen FROM filter WHERE mp = (SELECT id FROM measurementpoints WHERE MAMPid = '%s' LIMIT 1) filter_id='%d' LIMIT 1",
	               mampid_get(filter->MAMPid), ntohl(filter->id)) ){
		return;
	}

	MYSQL_RES* result = mysql_store_result(&connection);
	if ( !send_mysql_filter(marc, result, from, filter->MAMPid) ){
		Log::verbose("MArCd", "No filter matching {%02d}\n", ntohl(filter->id));
		MPMessage reply;
		reply.type = MP_FILTER_INVALID_ID;
		int ret;
		if ( (ret=marc_push_event(marc, &reply, from)) != 0 ){
			Log::fatal("MArCd", "marc_push_event() returned %d: %s\n", ret, strerror(ret));
		}
	}
	mysql_free_result(result);
}

static void __attribute__((unused)) MP_VerifyFilter(int sd, struct sockaddr from, char *buffer){
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
#warning following format warnings is from unused code that is fubar anyway
		sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', ind='%d', CI_ID='%s', VLAN_TCI='%d', VLAN_TCI_MASK='%d',ETH_TYPE='%d', ETH_TYPE_MASK='%d',ETH_SRC='%s',ETH_SRC_MASK='%s', ETH_DST='%s', ETH_DST_MASK='%s',IP_PROTO='%d', IP_SRC='%s', IP_SRC_MASK='%s', IP_DST='%s', IP_DST_MASK='%s', SRC_PORT='%d', SRC_PORT_MASK='%d', DST_PORT='%d', DST_PORT_MASK='%d', TYPE='%d', CAPLEN='%d', consumer='%d'",
		        MyVerify->MAMPid, f->filter_id, f->index, f->iface, f->vlan_tci, f->vlan_tci_mask,
		        f->eth_type,f->eth_type_mask,
		        hexdump_address_r(&f->eth_src, &buf[0]), hexdump_address_r(&f->eth_src_mask, &buf[17]),
		        hexdump_address_r(&f->eth_dst, &buf[34]), hexdump_address_r(&f->eth_dst_mask, &buf[51]),
		        f->ip_proto,
		        f->ip_src, f->ip_src_mask,
		        f->ip_dst, f->ip_dst_mask,
		        f->src_port,f->src_port_mask,f->dst_port,f->dst_port_mask,
		        stream_addr_type(&f->dest),
		        f->caplen,
		        f->consumer);

		sprintf(query, "%s, DESTADDR='%s' ", query, stream_addr_ntoa(&f->dest));
	}

	printf("MP_VerifyFilter():\n%s\n",query);
	if ( mysql_query(&connection, query) != 0 ) {
		Log::fatal("MArCd", "Failed to execute mysql query: %s\nThe query was: %s\n", mysql_error(&connection), query);
		return;
	}

	return;
}

static void MP_Distress(marc_context_t marc, const char* mampid, struct sockaddr* from){
	Log::fatal("MArCd", "Distress signal from MP (MAMPid: %s)\n", mampid);
	mp_set_status(mampid, MP_STATUS_DISTRESS);
}

static void mp_set_status(const char* mampid, enum MPStatusEnum status){
	char buf[16*2+1]; /* mampids are 16 bytes, worst-case escape requires n*2 chars + nullterminator */
	mysql_real_escape_string(&connection, buf, mampid, strlen(mampid));
	db_query("UPDATE measurementpoints SET status = %d WHERE MAMPid = '%s'", status, buf);
}
