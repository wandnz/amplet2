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

#ifndef _MEASURED_CONTROL_H
#define _MEASURED_CONTROL_H

#include <event2/event.h>

#include "acl.h"

/* control port is a string that gets given to getaddrinfo() */
#define DEFAULT_AMPLET_CONTROL_PORT "8869"

/* Allow the test server to run slightly longer than the client test */
#define TEST_SERVER_EXTRA_TIME 60

#define MEASURED_CONTROL_OK 200
#define MEASURED_CONTROL_BADREQUEST 400
#define MEASURED_CONTROL_FORBIDDEN 403
#define MEASURED_CONTROL_FAILED 500
#define MEASURED_CONTROL_NOTIMPLEMENTED 501

struct acl_event {
    struct acl_root *acl;
    struct event *control_read;
};

typedef struct amp_control {
    int enabled;
    char *port;
    char *interface;
    char *ipv4;
    char *ipv6;
    struct event *socket;
    struct event *socket6;
    struct event_base *base;
    struct acl_root *acl;
} amp_control_t;

int initialise_control_socket(struct event_base *base,
        amp_control_t *control);

void free_control_config(amp_control_t *control);
#endif
