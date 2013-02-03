/**
* Measurement Area Control Daemon
* Copyright (C) 2003-2013 (see AUTHORS)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "database.hpp"
#include "log.hpp"
#include "vcs.h"
#include <caputils/version.h>
#include <cstdarg>
#include <cstdlib>

MYSQL connection;
char db_hostname[64] = "localhost";
int  db_port = MYSQL_PORT;
char db_name[64] = {0,};
char db_username[64] = {0,};
char db_password[64] = {0,};
static const int marc_web_requirement = 1;

int db_connect(){
	Log::verbose("MArCd", "Connecting to mysql://%s@%s:%d/%s (using password: %s)\n",
	             db_username, db_hostname, db_port, db_name, db_password[0] != 0 ? "YES" : "NO");
  if ( !mysql_real_connect(&connection, db_hostname, db_username, db_password, db_name,db_port,0,0) ){
	  Log::fatal("MArCd", "Failed to connect to database: %s\n", mysql_error(&connection));
	  return 0;
  }

  if ( !db_query("SELECT `num` FROM `version` LIMIT 1") ){
	  Log::fatal("MArCd", "Database too old, run marc_web update script.\n");
	  return 0;
  }
  MYSQL_RES* result = mysql_use_result(&connection);
  MYSQL_ROW row = mysql_fetch_row(result);
  if ( atoi(row[0]) < marc_web_requirement ){
	  Log::fatal("MArCd", "Database too old, run marc_web update script.\n");
	  return 0;
  }
  mysql_free_result(result);

  const char* vcs =
  #ifdef HAVE_VCS
	  VCS_REV "/" VCS_BRANCH;
	#else
  "";
	#endif

  db_query("REPLACE `meta` (`key`, `value`) VALUES ('marcd_version', '%s')", VERSION);
  db_query("REPLACE `meta` (`key`, `value`) VALUES ('marcd_vcs', '%s')", vcs);
  db_query("REPLACE `meta` (`key`, `value`) VALUES ('marcd_caputils', '%s')", caputils_version(NULL));

  return 1;
}

int db_query(const char* sql, ...){
  char query[2000] = {0,};

  va_list ap;
  va_start(ap, sql);
  vsnprintf(query, sizeof(query), sql, ap);
  va_end(ap);

  if ( mysql_ping(&connection) != 0 ){
    Log::message("MArCd", "Connection to MySQL lost: %s\n", mysql_error(&connection));
    Log::message("MArCd", "Trying to reconnect.\n");
    if ( !db_connect() ){
	    return 0;
    }
  }

  Log::debug("MArCd", "Executing SQL query:\n  %s\n", query);

  if ( mysql_query(&connection,query) != 0 ) {
	  Log::fatal("MArCd", "Failed to execute MySQL query.\n");
	  Log::fatal("MArCd", "  Message: %s\n", mysql_error(&connection));
	  Log::fatal("MArCd", "  Query: %s\n", query);
    return 0;
  }

  return 1;
}
