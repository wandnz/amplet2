/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Jayden Hewer
 *         Brendon Jones
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

#ifndef _TESTS_FASTPING_H
#define _TESTS_FASTPING_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <sys/time.h>

#include "tests.h"
#include "testlib.h"

#define DEFAULT_FASTPING_PACKET_COUNT 60
#define DEFAULT_FASTPING_PACKET_RATE 1
#define DEFAULT_FASTPING_PACKET_SIZE 64
#define FASTPING_PACKET_LOSS_TIMEOUT 3

#define MAXIMUM_FASTPING_PACKET_COUNT 10000000
#define MAXIMUM_FASTPING_PACKET_RATE 100000

#define MINIMUM_FASTPING_PACKET_SIZE ( \
        sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(uint64_t))

#define RESPONSE_BUFFER_LEN ( \
        sizeof(struct iphdr) + 60 + sizeof(struct icmphdr) + 8)

const float PERCENTILES[] = {0.0, 0.1, 1.0, 5.0, 10.0, 20.0, 30.0, 40.0, 50.0,
    60.0, 70.0, 80.0, 90.0, 95.0, 99.0, 99.9, 100};
#define PERCENTILE_COUNT ((int)(sizeof(PERCENTILES) / sizeof(float)))


/* TODO investigate the time vs space tradeoff of writing the timestamp to
 * the outgoing packet and only keeping the RTT value once it returns
 */
struct info_t {
    struct timeval time_sent;
    struct timeval time_received;
};

struct summary_t {
    uint32_t maximum;
    uint32_t minimum;
    double mean;
    double sd;
    uint32_t samples;
};

struct opt_t {
    uint64_t count;
    uint64_t rate;
    uint64_t gap;
    uint16_t size;
    uint16_t preemptive;
    uint8_t dscp;
};


amp_test_result_t* run_fastping(int argc, char *argv[], int count,
    struct addrinfo **dests);
void print_fastping(amp_test_result_t *result);
test_t *register_test(void);
#endif
