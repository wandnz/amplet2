#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include "debug.h"



/*
 * These are both extern and can be set by config files or overridden to
 * maximum debug by command line options.
 * TODO is there a nicer way to do this?
 */
int log_level = LOG_INFO;
int log_level_override = 0;



/*
 * Using the log levels from syslog for easy integration later if desired.
 * This means that the highest priority messages have the lowest integer values.
 * Values range from LOG_EMERG=0 to LOG_DEBUG=7, so need to check that the
 * given priority is actually less than our logging level.
 *
 * LOG_ALERT: user action must be taken, program won't run (config files etc)
 * LOG_ERR: something has gone quite wrong, program will terminate
 * LOG_WARNING: something has gone wrong, but program will continue
 * LOG_NOTICE: normal but significant condition (not used yet? remove?)
 * LOG_INFO: informational but non-critical messages about program status
 * LOG_DEBUG: debug-level messages
 */
void Log(int priority, const char *fmt, ...)
{
    va_list ap;
    char buffer[513];
    char *prefix;
    time_t ts;
    char date[32];

    /* don't print anything if priority doesn't meet minimum requirements */
    if ( priority > log_level ) {
	return;
    }

    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    /* chop any newline that is in the error message */
    if ( buffer[strlen(buffer)-1] == '\n' )
	buffer[strlen(buffer)-1] = '\0';

#if LOG_TO_SYSLOG
    /* log to syslog if enabled and the program is running without a tty */
    if ( !isatty(fileno(stdout)) ) {
	syslog(priority, "%s", buffer);
        return;
    }
#endif

    /*
     * ideally this shouldn't be needed, but the syslog prioritynames array is
     * out of order and is all lowercase.
     */
    switch ( priority ) {
	case LOG_EMERG: prefix = "EMERG"; break;
	case LOG_ALERT: prefix = "ALERT"; break;
	case LOG_CRIT: prefix = "CRITICAL"; break;
	case LOG_ERR: prefix = "ERROR"; break;
	case LOG_WARNING: prefix = "WARNING"; break;
	case LOG_NOTICE: prefix = "NOTICE"; break;
	case LOG_INFO: prefix = "INFO"; break;
	case LOG_DEBUG: prefix = "DEBUG"; break;
	default: prefix = "???"; break;
    };

    /* format date and chop newline from end of formatted string */
    ts = time(NULL);
    ctime_r(&ts, date);
    date[strlen(date)-1] = '\0';

    /*
     * write the log message to the appropriate place: use stdout if it is
     * available to us, otherwise write to a log file
     */
    if ( isatty(fileno(stdout)) ) {
	fprintf(stderr, "%s %s: %s\n", date, prefix, buffer);
    } else {
	/* printing to a log file under our own control */
        /* TODO figure out the name of the current process for log message */
        /* TODO make sure this log directory actually exists */
	FILE *out;
	if ( (out = fopen(AMP_LOG_DIR "/amplet2.log", "a")) == NULL ) {
	    /* TODO something smart to report error in logging */
	    return;
	}
	fprintf(out, "%s %s: %s\n", date, prefix, buffer);
	fclose(out);
    }
}



/*
 * A more sensible inet_ntop that can figure out what to do for different
 * address families on its own. Takes an addrinfo structure (rather than a
 * in_addr or in6_addr), and a buffer to return the result in. Internally it
 * uses this information to call inet_ntop with sensible arguments.
 */
const char *amp_inet_ntop(struct addrinfo *addr, char *buffer) {
    void *addrptr;

    assert(addr);
    assert(buffer);

    switch ( addr->ai_family ) {
        case AF_INET: addrptr = &((struct sockaddr_in*)addr->ai_addr)->sin_addr;
                      break;
        case AF_INET6: addrptr = &((struct sockaddr_in6*)
                               addr->ai_addr)->sin6_addr;
                       break;
        default: snprintf(buffer, INET6_ADDRSTRLEN, "unknown"); return buffer;
    };

    return inet_ntop(addr->ai_family, addrptr, buffer, INET6_ADDRSTRLEN);
}
