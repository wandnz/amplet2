#ifndef _MEASURED_WATCHDOG_H
#define _MEASURED_WATCHDOG_H

#include "schedule.h"
#include "libwandevent.h"

/* number of seconds a test has between a warning SIGINT and the SIGKILL */
#define WATCHDOG_GRACE_PERIOD 30

int start_test_watchdog(test_t *test, timer_t *timerid);
int start_watchdog(time_t duration, int signal, timer_t *timerid);
int stop_watchdog(timer_t timerid);

void child_reaper(wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data);

#endif
