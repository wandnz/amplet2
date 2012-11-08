#ifndef _MEASURED_WATCHDOG_H
#define _MEASURED_WATCHDOG_H

#include "libwandevent.h"


void kill_running_test(struct wand_timer_t *timer);
void add_test_watchdog(wand_event_handler_t *ev_hdl, pid_t pid, uint16_t max);
void child_reaper(__attribute__((unused))struct wand_signal_t *signal);

#endif
