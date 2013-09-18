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
#endif /* HAVE_CONFIG_H */

#include "configfile.hpp"
#include "database.hpp"
#include "globals.hpp"
#include <errno.h>
#include <string>

extern "C" {
#include <iniparser.h>
}

static std::string config_filename;
typedef void (*param_callback)(const char*);

template <class T>
static void read_param_impl(T& dst, dictionary* src, const char* key);

template <>
void read_param_impl<bool>(bool& dst, dictionary* src, const char* key){
	int value = iniparser_getboolean(src, key, -1);
	if ( value == -1 ) return;
	dst = value;
}

template <>
void read_param_impl<char*>(char*& dst, dictionary* src, const char* key){
	const char* value = iniparser_getstring(src, key, NULL);
	if ( !value ) return;
	free(dst);
	dst = strdup(value);
}

template <class T>
static void read_param(T& dst, dictionary* src, const char* key){
	/* iniparser is not const correct and my strings is not writable */
	static char buf[64];
	snprintf(buf, sizeof(buf), "%s", key);

	read_param_impl(dst, src, key);
}

static void read_param(param_callback func, dictionary* src, const char* key){
	/* iniparser is not const correct and my strings is not writable */
	static char buf[64];
	snprintf(buf, sizeof(buf), "%s", key);

	const char* value = iniparser_getstring(src, key, NULL);
	if ( !value ) return;
	func(value);
}

static void read_param(char* dst, size_t bytes, dictionary* src, const char* key){
	/* iniparser is not const correct and my strings is not writable */
	static char buf[64];
	snprintf(buf, sizeof(buf), "%s", key);

	const char* value = iniparser_getstring(src, buf, NULL);
	if ( !value ) return;

	snprintf(dst, bytes, "%s", value);
}

const char* config::filename(){
	return !config_filename.empty() ? config_filename.c_str() : NULL;
}

int config::load(int argc, char* argv[]){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* program_name;
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	char* filename = NULL;
	dictionary* config = NULL;

	/* locate configuration filename. This is done before getopt since getopt has
	 * precedence over conf, so if this is run after getopt it would overwrite
	 * getopt instead of vice-versa. */
	for ( int i = 0; i < argc; i++ ){
		int a = strcmp(argv[i], "-f") == 0;
		int b = strcmp(argv[i], "--config") == 0;
		if ( !(a||b) ){
			continue;
		}

		if ( i+1 == argc ){
			fprintf(stderr, "%s: missing argument to %s.\n", program_name, argv[i]);
			return 1;
		}

		filename = strdup(argv[i+1]);
	}

	/* if no configuration file was explicitly required try default paths */
	if ( !filename ){
		/* try in sysconfdir ($prefix/etc by default) */
		char* tmp;
		int ret = asprintf(&tmp, "%s/%s", SYSCONF_DIR, MARCD_DEFAULT_CONFIG_FILE);
		if ( ret == -1 ){
			fprintf(stderr, "%s: %s\n", program_name, strerror(errno));
			exit(1);
		}

		if ( access(tmp, R_OK) == 0 ){
			filename = tmp;
		}

		/* try default filename in pwd (has precedence of sysconfdir) */
		if ( access(MARCD_DEFAULT_CONFIG_FILE, R_OK) == 0 ){
			free(filename);
			filename = strdup(MARCD_DEFAULT_CONFIG_FILE);
		}
	}

	/* if we still don't have a filename we ignore it, the user hasn't requested
	 * anything and no default could be located. */
	if ( !filename ){
		return 0;
	}

	/* parse configuration */
	config_filename = filename;
	if ( !(config=iniparser_load(filename)) ){
		return 1;
	}
	free(filename);

	/* mysql config */
	read_param(db_hostname, sizeof(db_hostname), config, "mysql:hostname");
	read_param(db_username, sizeof(db_username), config, "mysql:username");
	read_param(db_password, sizeof(db_password), config, "mysql:password");
	read_param(db_name,     sizeof(db_name),     config, "mysql:database");

	/* general */
	read_param(have_relay_daemon, config, "general:relay");
	read_param(set_control_ip, config, "general:listen");
	read_param(rrdpath, config, "general:datadir");

	return 0;
}

void config::set_control_ip(const char* addr){
	if ( inet_aton(addr, &control.addr) == 0 ){
		fprintf(stderr, "`%s' is not a valid IPv4 address\n", addr);
	}
}
