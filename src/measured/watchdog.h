#ifndef _MEASURED_WATCHDOG_H
#define _MEASURED_WATCHDOG_H

#include "libwandevent.h"


void kill_running_test(__attribute__((unused))wand_event_handler_t *ev_hdl,
        void *data);
void add_test_watchdog(wand_event_handler_t *ev_hdl, pid_t pid, uint16_t max,
        char *testname);
void child_reaper(wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data);

#endif
