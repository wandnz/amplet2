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
#include "dns.h"
#include "dns.pb-c.h"

#define TEST_TARGET "doesnotexist.invalid"

/*
 *
 */
int main(void) {
    amp_test_result_t *result;
    struct addrinfo *target;
    Amplet2__Dns__Report *msg;
    Amplet2__Dns__Item *item;
    int argc = 3;
    char *argv[] = {"amp-dns", "-q", "example.com", NULL};

    /*
     * create a dummy addrinfo like the resolver does when it can't resolve
     * the name
     */
    target = calloc(1, sizeof(struct addrinfo));
    target->ai_family = AF_INET;
    target->ai_addrlen = 0;
    target->ai_addr = NULL;
    target->ai_canonname = TEST_TARGET;
    target->ai_next = NULL;

    /* run the test against the dummy target */
    result = run_dns(argc, argv, 1, &target);

    assert(result);
    assert(result->data);

    /* check that the results are missing/empty in the right places */
    msg = amplet2__dns__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == 1);
    assert(msg->reports);

    item = msg->reports[0];

    assert(!item->has_address);
    assert(item->has_family);
    assert(item->family == AF_INET);
    assert(!item->has_rtt);
    assert(!item->has_query_length);
    assert(!item->has_response_size);
    assert(!item->has_total_answer);
    assert(!item->has_total_authority);
    assert(!item->has_total_additional);
    assert(!item->flags);
    assert(!item->has_ttl);
    assert(strcmp(item->name, TEST_TARGET) == 0);
    assert(!item->has_instance);
    assert(!item->has_rrsig);

    amplet2__dns__report__free_unpacked(msg, NULL);
    free(result->data);
    free(result);
    free(target);

    return 0;
}
