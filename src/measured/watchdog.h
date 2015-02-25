#ifndef _MEASURED_WATCHDOG_H
#define _MEASURED_WATCHDOG_H

#include "schedule.h"
#include "libwandevent.h"

/* number of seconds a test has between a warning SIGINT and the SIGKILL */
#define WATCHDOG_GRACE_PERIOD 30

void free_watchdog_schedule_item(kill_schedule_item_t *item);
void kill_running_test(wand_event_handler_t *ev_hdl, void *data);
void add_test_watchdog(wand_event_handler_t *ev_hdl, pid_t pid, uint16_t max,
        int sigint, char *testname);
void child_reaper(wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data);

#endif
