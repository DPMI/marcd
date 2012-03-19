#ifndef MARCD_LOG_H
#define MARCD_LOG_H

#include <cstdio>

namespace Log {
	enum Severity {
		FATAL,
		NORMAL,
		VERBOSE,
		DEBUG,
	};

	void fatal(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void message(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void verbose(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
	void debug(const char* component, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

	void set_file_destination(FILE* fp, Severity severity);

	#ifdef HAVE_SYSLOG
	void set_syslog_destinatin(Severity severity);
	#endif
};

#endif /* MARCD_LOG_H */
