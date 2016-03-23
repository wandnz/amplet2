#ifndef _MEASURED_TEST_H
#define _MEASURED_TEST_H

#include <openssl/bio.h>
#include <libwandevent.h>

#include "schedule.h"
//XXX WHY CANT THIS BE FOUND in schedule.h?
typedef struct test_schedule_item test_schedule_item_t;

void run_test(const test_schedule_item_t * const item, BIO *ctrl);
void run_scheduled_test(wand_event_handler_t *ev_hdl, void *data);

#endif
