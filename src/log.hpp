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

#ifndef MARCD_LOG_H
#define MARCD_LOG_H

#include <cstdio>

namespace Log {
	enum Severity {
		FATAL, /* fatal errors should always terminate application */
		ERROR,
		NORMAL,
		VERBOSE,
		DEBUG,
	};

	void fatal(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void error(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void message(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void verbose(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void debug(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

	void set_file_destination(FILE* fp, Severity severity);

	#ifdef HAVE_SYSLOG
	void set_syslog_destination(Severity severity);
	#endif

	/* for internal use only */
	typedef void (*log_callback)(const char* component, Log::Severity severity, const char* fmt, va_list ap);
	extern log_callback log;
};

#endif /* MARCD_LOG_H */
