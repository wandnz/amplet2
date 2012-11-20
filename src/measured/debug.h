#ifndef _MEASURED_DEBUG_H_
#define _MEASURED_DEBUG_H_

#include <syslog.h>

extern int log_level;

void Log(int priority, const char *fmt, ...);
#endif
