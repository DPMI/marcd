#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log.h"
#include <caputils/log.h>
#include <cstdio>
#include <cstdlib>
#include <stdarg.h>

#ifdef HAVE_SYSLOG
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#endif

typedef void (*log_callback)(const char* component, Log::Severity severity, const char* fmt, va_list ap);
static log_callback log = NULL;
static Log::Severity severity = Log::NORMAL;

static FILE* fp = NULL;;
static void file_log(const char* component, Log::Severity severity, const char* fmt, va_list ap){
	vlogmsg(fp, component, fmt, ap);
}

static void syslog_log(const char* component, Log::Severity severity, const char* fmt, va_list ap){
	static int level_lut[] = {
		LOG_CRIT,
		LOG_NOTICE,
		LOG_INFO,
		LOG_DEBUG,
	};

	vsyslog(level_lut[severity], fmt, ap);
}

void Log::fatal(const char* component, const char* fmt, ...){
	if ( severity < Log::FATAL ) return;
	va_list ap;
	va_start(ap, fmt);
	log(component, Log::FATAL, fmt, ap);
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
	char name[64];
	pid_t pid = getpid();
	snprintf(name, 64, "marcd[%d]", pid);
	openlog(name, 0, LOG_DAEMON);
	log = syslog_log;
	severity = s;
}
#endif
