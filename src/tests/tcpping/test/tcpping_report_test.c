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
#include "tcpping.h"
#include "tcpping.pb-c.h"


/* these are globals as we need to get them into the print callback */
struct info_t *info;
struct opt_t options;
unsigned int count;



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Tcpping__Header *b) {
    assert(b->has_random);
    assert(b->has_packet_size);
    assert(b->has_port);
    assert(a->random == b->random);
    assert(a->packet_size == b->packet_size);
    assert(a->port == b->port);
}



/*
 * Check that the address in the result item matches the address that the
 * test tried to report.
 */
static void verify_address(struct addrinfo *a, Amplet2__Tcpping__Item *b) {
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
 *
 */
static void verify_flags(struct info_t *a, Amplet2__Tcpping__TcpFlags *b) {
    assert(a);
    assert(b);

    if ( a->replyflags & 0x01 ) {
        assert(b->has_fin);
        assert(b->fin);
    } else {
        assert(!b->has_fin);
    }

    if ( a->replyflags & 0x02 ) {
        assert(b->has_syn);
        assert(b->syn);
    } else {
        assert(!b->has_syn);
    }

    if ( a->replyflags & 0x04 ) {
        assert(b->has_rst);
        assert(b->rst);
    } else {
        assert(!b->has_rst);
    }

    if ( a->replyflags & 0x08 ) {
        assert(b->has_psh);
        assert(b->psh);
    } else {
        assert(!b->has_psh);
    }

    if ( a->replyflags & 0x10 ) {
        assert(b->has_ack);
        assert(b->ack);
    } else {
        assert(!b->has_ack);
    }

    if ( a->replyflags & 0x20 ) {
        assert(b->has_urg);
        assert(b->urg);
    } else {
        assert(!b->has_urg);
    }
}



/*
 * Check that the RTT/TTL are present or not and have the correct values,
 * based on the same logic used when reporting.
 */
static void verify_response(struct info_t *a, Amplet2__Tcpping__Item *b) {
    /* ensure rtt is only set if there was a valid response */
    switch ( a->reply ) {
        case NO_REPLY:
            assert(!b->has_rtt);
            assert(!b->has_icmptype);
            assert(!b->has_icmpcode);
            assert(b->flags == NULL);
            break;

        case TCP_REPLY:
            assert(b->has_rtt);
            assert(a->delay == b->rtt);
            assert(!b->has_icmptype);
            assert(!b->has_icmpcode);
            assert(b->flags);
            verify_flags(a, b->flags);
            break;

        case ICMP_REPLY:
            assert(!b->has_rtt);
            assert(b->has_icmptype);
            assert(b->has_icmpcode);
            assert(a->icmptype == b->icmptype);
            assert(a->icmpcode == b->icmpcode);
            assert(b->flags == NULL);
            break;
    };
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Tcpping__Report *msg;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__tcpping__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == count);

    verify_header(&options, msg->header);

    /* check each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        verify_address(info[i].addr, msg->reports[i]);
        verify_response(&info[i], msg->reports[i]);
    }

    amplet2__tcpping__report__free_unpacked(msg, NULL);
}



/*
 *
 */
static void build_info(struct info_t *item, struct addrinfo *addr,
                enum reply_type reply, uint32_t delay, uint8_t flags,
                uint8_t code, uint8_t type) {

    item->addr = addr;
    item->reply = reply;
    item->delay = delay;
    item->replyflags = flags;
    item->icmptype = type;
    item->icmpcode = code;
}



/*
 *
 */
int main(void) {
    struct timeval start_time;
    struct addrinfo *addr = get_numeric_address("192.168.0.254", NULL);
    addr->ai_canonname = strdup("foo.bar.baz");

    count = 24;
    info = (struct info_t*)malloc(sizeof(struct info_t) * count);

    /* NO_REPLY, with various fields set that should be ignored */
    build_info(&info[0], addr, NO_REPLY, 0, 0x0, 0, 0);
    build_info(&info[1], addr, NO_REPLY, 1, 0x01, 0, 1);
    build_info(&info[2], addr, NO_REPLY, 256, 0x02, 1, 0);
    build_info(&info[3], addr, NO_REPLY, 512, 0x0c, 1, 1);
    build_info(&info[4], addr, NO_REPLY, 1024, 0x10, 3, 0);
    build_info(&info[5], addr, NO_REPLY, 2048, 0x30, 3, 9);
    build_info(&info[6], addr, NO_REPLY, 65536, 0x0f, 11, 0);
    build_info(&info[7], addr, NO_REPLY, 4294967295U, 0x3f, 12, 2);

    /* TCP_REPLY */
    build_info(&info[8], addr, TCP_REPLY, 0, 0x0, 0, 0);
    build_info(&info[9], addr, TCP_REPLY, 1, 0x01, 0, 1);
    build_info(&info[10], addr, TCP_REPLY, 256, 0x02, 1, 0);
    build_info(&info[11], addr, TCP_REPLY, 512, 0x0c, 1, 1);
    build_info(&info[12], addr, TCP_REPLY, 1024, 0x10, 3, 0);
    build_info(&info[13], addr, TCP_REPLY, 2048, 0x30, 3, 9);
    build_info(&info[14], addr, TCP_REPLY, 65536, 0x0f, 11, 0);
    build_info(&info[15], addr, TCP_REPLY, 4294967295U, 0x3f, 12, 2);

    /* ICMP_REPLY */
    build_info(&info[16], addr, ICMP_REPLY, 0, 0x0, 0, 0);
    build_info(&info[17], addr, ICMP_REPLY, 1, 0x01, 0, 1);
    build_info(&info[18], addr, ICMP_REPLY, 256, 0x02, 1, 0);
    build_info(&info[19], addr, ICMP_REPLY, 512, 0x0c, 1, 1);
    build_info(&info[20], addr, ICMP_REPLY, 1024, 0x10, 3, 0);
    build_info(&info[21], addr, ICMP_REPLY, 2048, 0x30, 3, 9);
    build_info(&info[22], addr, ICMP_REPLY, 65536, 0x0f, 11, 0);
    build_info(&info[23], addr, ICMP_REPLY, 4294967295U, 0x3f, 12, 2);

    /* try some different combinations of header options */
    options.packet_size = 0;
    options.random = 0;
    options.port = 22;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 64;
    options.random = 0;
    options.port = 53;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 84;
    options.random = 0;
    options.port = 80;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 1500;
    options.random = 0;
    options.port = 443;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 9000;
    options.random = 0;
    options.port = 65535;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    free(info);
    freeaddrinfo(addr);
    return 0;
}
