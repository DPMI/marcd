/**
* Measurement Area Control Daemon
* Copyright (C) 2003-2014 (see AUTHORS)
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
#endif /* HAVE_CONFIG_H */

#include "configfile.hpp"
#include "database.hpp"
#include "globals.hpp"
#include <errno.h>
#include <cstdio>
#include <pwd.h>
#include <grp.h>
#include <string>

void config::set_control_ip(const char* addr){
	if ( inet_aton(addr, &control.addr) == 0 ){
		fprintf(stderr, "`%s' is not a valid IPv4 address\n", addr);
	}
}

void config::set_drop_username(const char* username){
	const struct passwd* passwd = getpwnam(username);
	if ( !passwd ){
		fprintf(stderr, "No such user `%s', ignored.\n", username);
		return;
	}
	drop_uid = passwd->pw_uid;
	drop_username = username;
}

void config::set_drop_group(const char* groupname){
	const struct group* group = getgrnam(groupname);
	if ( !group ){
		fprintf(stderr, "No such group `%s', ignored.\n", groupname);
		return;
	}
	drop_gid = group->gr_gid;
	drop_group = groupname;
}
