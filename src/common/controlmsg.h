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

#ifndef _COMMON_CONTROLMSG_H
#define _COMMON_CONTROLMSG_H

#include <stdint.h>
#include <openssl/bio.h>
#include <google/protobuf-c/protobuf-c.h>

#include "tests.h"

/* TODO this should be adjusted based on the expected test duration? Short when
 * exchanging messages, longer when waiting for test results. Or should the
 * remote client program just call read multiple times till it hits the
 * expected duration?
 */
#define CONTROL_CONNECTION_TIMEOUT 60

/* arbitrary cap to make sure massive amounts of memory aren't allocated */
#define MAX_CONTROL_MESSAGE_SIZE (1024 * 1024 * 10)


int write_control_packet(BIO *ctrl, void *data, uint32_t len);
int read_control_packet(BIO *ctrl, void **data);

int send_control_hello(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_ready(test_type_t test, BIO *ctrl, uint16_t port);
int send_control_receive(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_send(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_result(test_type_t test, BIO *ctrl, ProtobufCBinaryData *data);
//XXX throughput specific
int send_control_renew(test_type_t test, BIO *ctrl);

int read_control_hello(test_type_t test, BIO *ctrl, void **options,
        void *(*parse_func)(ProtobufCBinaryData *data));
int read_control_ready(test_type_t test, BIO *ctrl, uint16_t *port);
int read_control_result(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *results);

/* extract data from send/receive for remote servers (udp, throughput) */
int parse_control_receive(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_send(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));

#endif
