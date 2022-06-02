/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MEASURED_PARSECONFIG_H
#define _MEASURED_PARSECONFIG_H

#include <confuse.h>
#include <unbound.h>

#include "global.h"
#include "control.h"
#include "schedule.h"

int get_loglevel_config(cfg_t *cfg);
char *get_change_user_config(cfg_t *cfg);
int should_config_rabbit(cfg_t *cfg);
int should_wait_for_cert(cfg_t *cfg);
int should_wait_for_clock_sync(cfg_t *cfg);
amp_control_t* get_control_config(cfg_t *cfg, amp_test_meta_t *meta);
fetch_schedule_item_t* get_remote_schedule_config(cfg_t *cfg);
amp_test_meta_t* get_interface_config(cfg_t *cfg, amp_test_meta_t *meta);
struct ub_ctx* get_dns_context_config(cfg_t *cfg, amp_test_meta_t *meta);
void get_default_test_args(cfg_t *cfg);
cfg_t* parse_config(char *filename, struct amp_global_t *vars);

#endif
