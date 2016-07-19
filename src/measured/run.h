#ifndef _MEASURED_RUN_H
#define _MEASURED_RUN_H

#include <openssl/bio.h>
#include <libwandevent.h>

#include "schedule.h"

void run_test(const test_schedule_item_t * const item, BIO *ctrl);
void run_scheduled_test(wand_event_handler_t *ev_hdl, void *data);

#endif
