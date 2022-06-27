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

#ifndef _COMMON_SERVERLIB_H
#define _COMMON_SERVERLIB_H

#include <stdint.h>
#include <openssl/bio.h>

#include "tests.h"
#include "testlib.h"
#include "measured.pb-c.h"

#define MAXIMUM_SERVER_WAIT_TIME 60000000


int start_listening(struct socket_t *sockets, int port,
        struct sockopt_t *sockopts);
BIO* listen_control_server(uint16_t port, uint16_t portmax,
        struct sockopt_t *sockopts);
int start_remote_server(BIO *ctrl, uint64_t type, char *params);
BIO* connect_control_server(struct addrinfo *dest, uint16_t port,
        struct sockopt_t *sockopts);
int connect_to_server(struct addrinfo *dest, uint16_t port,
        struct sockopt_t *sockopts);
void close_control_connection(BIO *ctrl);

//XXX is this the correct location for this function? serverlib.c?
int read_measured_response(BIO *ctrl, Amplet2__Measured__Response *response);
int send_measured_response(BIO *ctrl, uint32_t code, char *message);
int send_measured_result(BIO *ctrl, uint64_t type, amp_test_result_t *data);
int parse_measured_response(void *data, uint32_t len,
        Amplet2__Measured__Response *response);
#endif
