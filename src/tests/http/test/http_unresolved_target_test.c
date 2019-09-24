/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2019 The University of Waikato, Hamilton, New Zealand.
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

#include <assert.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "tests.h"
#include "http.h"
#include "http.pb-c.h"

#define TEST_HOST "http://doesnotexist.invalid"
#define TEST_URL TEST_HOST "/"

/*
 *
 */
int main(void) {
    amp_test_result_t *result;
    Amplet2__Http__Report *msg;
    Amplet2__Http__Server *server;
    int argc = 3;
    char *argv[] = {"amp-http", "-u", TEST_URL, NULL};

    /* run the test against the dummy target */
    result = run_http(argc, argv, 0, NULL);

    assert(result);
    assert(result->data);

    /* check that the results are missing/empty in the right places */
    msg = amplet2__http__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(strcmp(msg->header->url, TEST_URL) == 0);
    assert(msg->header->has_duration);
    assert(msg->header->duration == 0);
    assert(msg->header->has_total_bytes);
    assert(msg->header->total_bytes == 0);
    assert(msg->header->has_total_objects);
    assert(msg->header->total_objects == 0);

    assert(msg->n_servers == 1);
    assert(msg->servers);

    server = msg->servers[0];

    assert(strcmp(server->hostname, TEST_HOST) == 0);
    assert(server->has_start);
    assert(server->has_end);
    assert(server->start == server->end);
    assert(server->address);
    assert(strcmp(server->address, "0.0.0.0") == 0);
    assert(server->has_total_bytes);
    assert(server->total_bytes == 0);
    assert(server->n_objects == 0);

    amplet2__http__report__free_unpacked(msg, NULL);
    free(result->data);
    free(result);

    return 0;
}
