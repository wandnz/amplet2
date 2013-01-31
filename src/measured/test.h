#ifndef _MEASURED_TEST_H
#define _MEASURED_TEST_H

#include <stdint.h>
#include <libwandevent.h>

test_type_t get_test_id(const char *testname);
void run_scheduled_test(struct wand_timer_t *timer);

#endif
