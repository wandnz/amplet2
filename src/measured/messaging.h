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

#ifndef _MEASURED_MESSAGING_H
#define _MEASURED_MESSAGING_H

#include <amqp.h>
#include "tests.h"


/* local broker will persist it for us and send to master server later */
#define AMQP_SERVER "localhost"

/* 5672 is default, 5671 for SSL */
#define AMQP_PORT 5672

/* vhost "/" is the default */
#define AMQP_VHOST "/"

/* 128KB, recommended default */
#define AMQP_FRAME_MAX 131072

/* exchange and routing key used to report to the local broker */
#define AMQP_LOCAL_EXCHANGE ""
#define AMQP_LOCAL_ROUTING_KEY "report"

/*
 * TODO: this should be maintained for the lifetime of the main process, but
 * is currently just created and set by the individual test processes.
 */
amqp_connection_state_t conn;

int report_to_broker(test_t *test, amp_test_result_t *result);

#endif
