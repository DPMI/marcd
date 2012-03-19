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
