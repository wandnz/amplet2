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
#include "udpstream.h"
#include "udpstream.pb-c.h"


/* these are globals as we need to get them into the print callback */
struct opt_t options;
unsigned int count;
struct addrinfo *addr;



/*
 *
 */
#if 0
static struct test_request_t* build_info(struct test_request_t *next,
        enum tput_type direction, uint64_t start, uint64_t end,
        uint64_t bytes) {

    struct test_request_t *item;
    struct test_result_t *result;

    item = (struct test_request_t*)malloc(sizeof(struct test_request_t)*count);
    item->type = direction;
    item->next = next;
    item->s_web10g = NULL;
    item->c_web10g = NULL;

    result = (struct test_result_t*)malloc(sizeof(struct test_result_t));
    result->start_ns = start * 1000000000;
    result->end_ns = end * 1000000000;
    result->bytes = bytes;

    if ( item->type == TPUT_2_CLIENT ) {
        item->c_result = result;
        item->s_result = malloc(sizeof(struct test_result_t));
    } else {
        item->s_result = result;
        item->c_result = malloc(sizeof(struct test_result_t));
    }

    return item;
}
#endif



/*
 *
 */
static void verify_voip(Amplet2__Udsptream__Item *a,
        Amplet2__Udpstream__voip *b) {

    assert(a);
    assert(b);

    assert(b->has_icpif);
    assert(b->has_cisco_mos);
    assert(b->has_itu_rating);
    assert(b->has_itu_mos);
}



/*
 *
 */
static void verify_summary(struct summary_t *a,
        Amplet2__Udpstream__SummaryStats *b) {

    assert(a);
    assert(b);

    assert(b->has_maximum);
    assert(a->maximum == b->maximum);
    assert(b->has_minimum);
    assert(a->minimum == b->minimum);
    assert(b->has_mean);
    assert(a->mean == b->mean);
    assert(b->has_samples);
    assert(a->samples == b->samples);
}



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Udpstream__Header *b) {
    assert(b->has_packet_size);
    assert(a->packet_size == b->packet_size);
    assert(b->has_packet_count);
    assert(a->packet_count == b->packet_count);
    assert(b->has_packet_spacing);
    assert(a->packet_spacing == b->packet_spacing);
    assert(b->has_percentile_count);
    assert(a->percentile_count == b->percentile_count);
    assert(b->has_rtt_samples);
    assert(a->rtt_samples == b->rtt_samples);
    assert(b->has_dscp);
    assert(a->dscp == b->dscp);
}



/*
 * Check that the address in the result item matches the address that the
 * test tried to report.
 */
static void verify_address(struct addrinfo *a, Amplet2__Udpstream__Header *b) {
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
 * Check that the measurements are present or not and have the correct values.
 */
static void verify_response(struct test_request_t *a,
        Amplet2__Udpstream__Item *b) {

    assert(b->has_direction);
    assert((int)a->type == (int)b->direction);

    /* XXX these might not all be present */
    assert(b->has_rtt);
    verify_summary(b->rtt);
    assert(b->has_jitter);
    verify_summary(b->jitter);
    assert(b->has_voip);
    verify_voip(b->voip);

    assert(b->has_percentiles);
    assert(b->has_packets_received);
    assert(b->loss_periods);
    assert(b->loss_percent);
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Udpstream__Report *msg;
    struct test_request_t *tmpinfo;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__udpstream__report__unpack(NULL, result->len, result->data);
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

    amplet2__udpstream__report__free_unpacked(msg, NULL);
}



/*
 *
 */
int main(void) {
    addr = get_numeric_address("192.168.0.254", NULL);
    addr->ai_canonname = strdup("foo.bar.baz");

    /*
     * try some different combinations of header options, they don't need to
     * relate to the results reported (but maybe that should be enforced?)
     */
    for ( i = 0; i < count; i++ ) {
        verify_message(amp_test_report_results(0, addr, &options));
    }

    freeaddrinfo(addr);
    return 0;
}
