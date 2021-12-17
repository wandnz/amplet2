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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "throughput.h"
#include "throughput.pb-c.h"


/* these are globals as we need to get them into the print callback */
struct test_request_t *info;
struct opt_t options;
unsigned int count;
struct addrinfo *addr;



/*
 *
 */
static void free_info(void) {
    struct test_request_t *tmp;
    assert(info);

    while ( info != NULL ) {
        tmp = info;
        info = info->next;

        if ( tmp->result ) {
            if ( tmp->result->tcpinfo ) {
                free(tmp->result->tcpinfo);
                tmp->result->tcpinfo = NULL;
            }
            free(tmp->result);
            tmp->result = NULL;
        }

        free(tmp);
    }
}



/*
 *
 */
static struct test_request_t* build_info(struct test_request_t *next,
        Amplet2__Throughput__Item__Direction direction,
        uint64_t start, uint64_t end, uint64_t bytes) {

    struct test_request_t *item;
    struct test_result_t *result;

    item = (struct test_request_t*)malloc(sizeof(struct test_request_t)*count);
    item->direction = direction;
    item->next = next;

    result = (struct test_result_t*)malloc(sizeof(struct test_result_t));
    result->start_ns = start * 1000000000;
    result->end_ns = end * 1000000000;
    result->bytes = bytes;
    /* TODO add tcpinfo */
    result->tcpinfo = NULL;

    item->result = result;

    return item;
}



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Throughput__Header *b) {
    assert(b->has_write_size);
    assert(a->write_size == b->write_size);
    assert(strcmp(a->textual_schedule, b->schedule) == 0);
}



/*
 * Check that the address in the result item matches the address that the
 * test tried to report.
 */
static void verify_address(struct addrinfo *a, Amplet2__Throughput__Header *b) {
    assert(b->has_family);
    assert(b->has_address);

    /* ensure family matches */
    assert(a->ai_family == b->family);

    /* ensure address length and address match */
    switch ( a->ai_family ) {
        case AF_INET:
            assert(b->address.len == sizeof(struct in_addr));
            assert(memcmp(b->address.data,
                        &((struct sockaddr_in*)a->ai_addr)->sin_addr,
                        sizeof(struct in_addr)) == 0);
            break;

        case AF_INET6:
            assert(b->address.len == sizeof(struct in6_addr));
            assert(memcmp(b->address.data,
                        &((struct sockaddr_in6*)a->ai_addr)->sin6_addr,
                        sizeof(struct in6_addr)) == 0);
            break;

        default: assert(0);
    };

    /* ensure the target names match */
    assert(strcmp(b->name, a->ai_canonname) == 0);
}



/*
 * Check that the RTT/TTL are present or not and have the correct values,
 * based on the same logic used when reporting.
 */
static void verify_response(struct test_request_t *a,
        Amplet2__Throughput__Item *b) {

    assert(b->has_direction);
    assert((int)a->direction == (int)b->direction);
    assert(b->has_duration);
    assert(a->result->end_ns - a->result->start_ns == b->duration);
    assert(b->has_bytes);
    assert(a->result->bytes == b->bytes);
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Throughput__Report *msg;
    struct test_request_t *tmpinfo;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__throughput__report__unpack(NULL, result->len, result->data);
    tmpinfo = info;

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == count);

    verify_header(&options, msg->header);
    verify_address(addr, msg->header);

    /* check each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        verify_response(tmpinfo, msg->reports[i]);
        /* advance to the next set of test results */
        tmpinfo = tmpinfo->next;
    }

    amplet2__throughput__report__free_unpacked(msg, NULL);
}



/*
 *
 */
int main(void) {
    addr = get_numeric_address("192.168.0.254", NULL);
    addr->ai_canonname = strdup("foo.bar.baz");

    count = 26;

    /* direction, start, end, bytes */
    info = build_info(NULL,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            0, 1000, 12345);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            0, 0, 0);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            0, 0, 1);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            1, 1, 0);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            1, 1, 1);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            1, 2, 1);

    /* around the current time and date */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            1439265634, 1439265634, 256);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            1439265634, 1439265664, 65536);

    /* around 2^16 */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            65536, 65536, 65536);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            65536, 65537, 65537);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            65535, 65597, 65535);

    /* around 2^31 */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            2147483648, 2147483648, 2147483648);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            2147483648, 2147483649, 2147483649);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            2147483647, 2147483699, 2147483647);

    /* around 2^32 */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            4294967296, 4294967296, 4294967296);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            4294967296, 4294967297, 4294967297);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            4294967295, 4294967397, 4294967295);

    /* around 2^33 */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            8589934592, 8589934592, 8589934592);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            8589934592, 8589934593, 8589934593);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            8589934591, 8589934793, 8589934592);

    /* around 2^34 */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            17179869184, 17179869184, 17179869184);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            17179869184, 17179869185, 17179869185);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            17179869183, 17179869884, 17179869183);

    /* around max value (2^64 / 1000000000 because times are in nanoseconds)) */
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            18446744073, 18446744073, 18446744073);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            18446744072, 18446744073, 9223372036854775808U);
    info = build_info(info,
            AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            9223372036U, 18446744073, 18446744073709551615U);

    options.schedule = info;

    /*
     * try some different combinations of header options, they don't need to
     * relate to the results reported (but maybe that should be enforced?)
     */
    options.write_size = 0;
    options.textual_schedule = "s1000,r,S2000";
    verify_message(amp_test_report_results(0, addr, &options));

    options.write_size = 84;
    options.textual_schedule = "t1000,r,T2000";
    verify_message(amp_test_report_results(0, addr, &options));

    options.write_size = DEFAULT_WRITE_SIZE;
    options.textual_schedule = "s0,s4294967296";
    verify_message(amp_test_report_results(0, addr, &options));

    options.write_size = 4294967295U;
    options.textual_schedule = "s4294967296,s4294967296";
    verify_message(amp_test_report_results(0, addr, &options));

    free_info();
    free(info);
    freeaddrinfo(addr);
    return 0;
}
