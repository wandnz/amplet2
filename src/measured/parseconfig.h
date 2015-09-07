#ifndef _MEASURED_PARSECONFIG_H
#define _MEASURED_PARSECONFIG_H

#include <confuse.h>
#include <unbound.h>

#include "global.h"
#include "control.h"
#include "schedule.h"

int get_loglevel_config(cfg_t *cfg);
int should_config_rabbit(cfg_t *cfg);
int should_wait_for_cert(cfg_t *cfg);
amp_control_t* get_control_config(cfg_t *cfg, amp_test_meta_t *meta);
fetch_schedule_item_t* get_remote_schedule_config(cfg_t *cfg);
amp_test_meta_t* get_interface_config(cfg_t *cfg, amp_test_meta_t *meta);
struct ub_ctx* get_dns_context_config(cfg_t *cfg, amp_test_meta_t *meta);
cfg_t* parse_config(char *filename, struct amp_global_t *vars);

#endif
