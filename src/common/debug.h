#ifndef _MEASURED_DEBUG_H_
#define _MEASURED_DEBUG_H_

#include <syslog.h>
#include <netdb.h>

/* XXX this won't work with tests if we execv to them? */
extern int log_level;
extern int log_level_override;

void Log(int priority, const char *fmt, ...);
const char *amp_inet_ntop(struct addrinfo *addr, char *buffer);
#endif
