#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log.hpp"
#include <caputils/log.h>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>

#ifdef HAVE_SYSLOG
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#endif

typedef void (*log_callback)(const char* component, Log::Severity severity, const char* fmt, va_list ap);
static Log::Severity severity = Log::NORMAL;

static FILE* fp = stderr;
static void file_log(const char* component, Log::Severity severity, const char* fmt, va_list ap){
	vlogmsg(fp, component, fmt, ap);
}

static char name[64];
static void syslog_log(const char* component, Log::Severity severity, const char* fmt, va_list ap){
	static int level_lut[] = {
		LOG_CRIT,
		LOG_ERR,
		LOG_NOTICE,
		LOG_INFO,
		LOG_DEBUG,
	};

	vsyslog(level_lut[severity], fmt, ap);
}

namespace Log {
	log_callback log = file_log;
}

void Log::fatal(const char* component, const char* fmt, ...){
	if ( severity < Log::FATAL ) return;
	va_list ap;
	va_list ap2;
	va_start(ap, fmt);
	va_copy(ap2, ap);
	log(component, Log::FATAL, fmt, ap);

	/* always log fatal to stderr */
	if ( log != file_log ){
		fp = stderr;
		file_log(component, Log::FATAL, fmt, ap2);
	}

	va_end(ap);
	va_end(ap2);
}

void Log::error(const char* component, const char* fmt, ...){
	if ( severity < Log::ERROR ) return;
	va_list ap;
	va_start(ap, fmt);
	log(component, Log::ERROR, fmt, ap);
	va_end(ap);
}

void Log::message(const char* component, const char* fmt, ...){
	if ( severity < Log::NORMAL ) return;
	va_list ap;
	va_start(ap, fmt);
	log(component, Log::NORMAL, fmt, ap);
	va_end(ap);
}

void Log::verbose(const char* component, const char* fmt, ...){
	if ( severity < Log::VERBOSE ) return;
	va_list ap;
	va_start(ap, fmt);
	log(component, Log::VERBOSE, fmt, ap);
	va_end(ap);
}

void Log::debug(const char* component, const char* fmt, ...){
	if ( severity < Log::DEBUG ) return;
	va_list ap;
	va_start(ap, fmt);
	log(component, Log::DEBUG, fmt, ap);
	va_end(ap);
}

void Log::set_file_destination(FILE* dst, Severity s){
	if ( !dst ){
		fprintf(stderr, "invalid log destination.\n");
		abort();
	}

	fp = dst;
	log = file_log;
	severity = s;
}

#ifdef HAVE_SYSLOG
void Log::set_syslog_destination(Severity s){
	pid_t pid = getpid();
	snprintf(name, 64, "marcd[%d]", pid);
	openlog(name, 0, LOG_DAEMON);
	log = syslog_log;
	severity = s;
}
#endif
