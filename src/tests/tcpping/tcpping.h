/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Shane Alcock
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

#ifndef _TESTS_TCPPING_H_
#define _TESTS_TCPPING_H_

#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdint.h>
#include <event2/event.h>

#include "tests.h"
#include "testlib.h"


/* The extra 4 bytes allows us to at least include an MSS option in the SYN */
#define MIN_TCPPING_PROBE_LEN ( \
    sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + 4)

#define MAX_TCPPING_PROBE_LEN 1500

#define DEFAULT_TCPPING_PORT 80

/*
 * Generally, we only need the TCP header of the response (no options) but
 * if we get an ICMP response we'll need enough space to store the headers
 * from the original packet...
 */
#define RESPONSE_BUFFER_LEN (300)

/* timeout in sec to wait before declaring the response lost, currently 10s */
#define LOSS_TIMEOUT 10

enum reply_type {
    NO_REPLY = 0,
    TCP_REPLY = 1,
    ICMP_REPLY = 2,
};

/*
 * User defined test options to control packet size and timing.
 */
struct opt_t {
    int random;                 /* Use random packet sizes (bytes) */
    int perturbate;             /* Delay sending by up to this time (usec) */
    uint16_t packet_size;       /* Use this particular packet size (bytes) */
    uint16_t port;              /* Target port number */
    uint32_t inter_packet_delay;/* minimum gap between packets (usec) */
    uint8_t dscp;
};

struct tcppingglobals {
    struct opt_t options;
    int seqindex;
    struct addrinfo **dests;
    struct addrinfo *sourcev4;
    struct addrinfo *sourcev6;
    uint16_t sourceportv4;
    uint16_t sourceportv6;
    struct socket_t raw_sockets;
    struct socket_t tcp_sockets;
    struct info_t *info;
    int destindex;
    int destcount;
    char *device;
    int outstanding;

    struct event_base *base;
    struct event *nextpackettimer;
    struct event *losstimer;
};


/* Pseudoheader for TCP checksum, IPv4 */
struct pseudotcp_ipv4 {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

/* Pseudoheader for TCP checksum, IPv6 */
struct pseudotcp_ipv6 {
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint32_t length;
    uint16_t zero_1;
    uint8_t zero_2;
    uint8_t next;
};

struct tcpmssoption {
    uint8_t mssopt;
    uint8_t msssize;
    uint16_t mssvalue;
};

/*
 * Describes each SYN packet that was sent and the response that was
 * received.
 */
struct info_t {
    struct sockaddr_storage source; /* Source IP address for the probe */
    struct addrinfo *addr;      /* Address that was probed */
    struct timeval time_sent;   /* Time when the SYN was sent */
    uint32_t seqno;             /* Sequence number of the sent SYN */
    uint32_t delay;             /* Delay in receiving response */
    enum reply_type reply;      /* Protocol of reply (TCP/ICMP) */
    uint8_t replyflags;         /* TCP control bits set in the reply */
    uint8_t icmptype;           /* ICMP type of the reply */
    uint8_t icmpcode;           /* ICMP code of the reply */
};

amp_test_result_t* run_tcpping(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_tcpping(amp_test_result_t *result);
test_t *register_test(void);

#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt);
#endif

#endif

/* vim: set sw=4 tabstop=4 softtabstop=4 expandtab : */
