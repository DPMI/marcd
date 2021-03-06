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

#include "utils.hpp"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

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

char* inet_ntoa_r(struct in_addr in, char* dst){
	strcpy(dst, inet_ntoa(in));
	return dst;
}
