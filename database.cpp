#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "database.h"
#include <libmarc/log.h>

extern int verbose_flag;
extern int debug_flag;
extern FILE* verbose;

MYSQL connection;
char db_hostname[64] = "localhost";
int  db_port = MYSQL_PORT;
char db_name[64] = {0,};
char db_username[64] = {0,};
char db_password[64] = {0,};

int db_connect(){
  logmsg(verbose, "[control] Connecting to mysql://%s@%s:%d/%s (using password: %s)\n",
	 db_username, db_hostname, db_port, db_name, db_password[0] != 0 ? "YES" : "NO");
  if ( !mysql_real_connect(&connection, db_hostname, db_username, db_password, db_name,db_port,0,0) ){
    logmsg(stderr, "[control] Failed to connect to database: %s\n", mysql_error(&connection));
    return 0;
  }
  return 1;
}

int db_query(const char* sql, ...){
  char query[2000] = {0,};

  va_list ap;
  va_start(ap, sql);
  vsnprintf(query, sizeof(query), sql, ap);
  va_end(ap);

  if ( mysql_ping(&connection) != 0 ){
    logmsg(stderr, "[control] Connection to MySQL lost: %s\n", mysql_error(&connection));
    logmsg(stderr, "[control] Trying to reconnect.\n");
    if ( !db_connect() ){
      return 0;
    }
  }

  if ( debug_flag ){
    logmsg(verbose, "[control] Executing SQL query:\n%s\n", query);
  }

  if ( mysql_query(&connection,query) != 0 ) {
    logmsg(stderr, "[control] Failed to execute MySQL query: %s\nThe query was: %s\n", mysql_error(&connection), query);
    return 0;
  }

  return 1;
}
