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

#ifndef MARCD_DATABASE_H
#define MARCD_DATABASE_H

#include <mysql.h>
#include <errmsg.h> /* from mysql */

int db_connect();
int db_query(const char* sql, ...) __attribute__ ((format (printf, 1, 2)));

extern MYSQL connection;
extern char db_hostname[64];
extern int  db_port;
extern char db_name[64];
extern char db_username[64];
extern char db_password[64];

#endif /* MARCD_DATABASE_H */
