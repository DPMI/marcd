#ifndef MARCD_DATABASE_H
#define MARCD_DATABASE_H

#include <mysql.h>
#include <errmsg.h> /* from mysql */

int db_connect();
int db_query(const char* sql, ...);

extern MYSQL connection;
extern char db_hostname[64];
extern int  db_port;
extern char db_name[64];
extern char db_username[64];
extern char db_password[64];

#endif /* MARCD_DATABASE_H */
