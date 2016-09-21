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

#ifndef _TESTS_TRACEROUTE_H
#define _TESTS_TRACEROUTE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip6.h>

#include "tests.h"
#include "testlib.h"


#define DEFAULT_TRACEROUTE_PROBE_LEN 60

#define MIN_TRACEROUTE_PROBE_LEN (sizeof(struct ip6_hdr) + \
        sizeof(struct udphdr) + sizeof(struct ipv6_body_t))

/* timeout in seconds to wait before declaring a response lost, currently 2s */
#define LOSS_TIMEOUT 2
#define LOSS_TIMEOUT_US (LOSS_TIMEOUT * 1000000)

/* TODO we can do this better than a fixed size buffer */
#define MAX_HOPS_IN_PATH 30

/* Destination port for the UDP probe packets */
#define TRACEROUTE_DEST_PORT 33434

/* TTL to use for the first probe packet */
#define MIN_INITIAL_TTL 3
#define MAX_INITIAL_TTL 8

/* Maximum number of destinations that can have probe packets outstanding */
#define INITIAL_WINDOW 50

/* number of times to retry at a particular TTL to elicit a response */
#define TRACEROUTE_RETRY_LIMIT 2

/* number of consecutive timeouts required before giving up on a path */
#define TRACEROUTE_NO_REPLY_LIMIT 5

#define HOP_ADDR(ttl) (item->hop[ttl - 1].addr)
#define HOP_REPLY(ttl) (item->hop[ttl - 1].reply)

amp_test_result_t* run_traceroute(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_traceroute(amp_test_result_t *result);
test_t *register_test(void);

#if UNIT_TEST
int amp_traceroute_build_ipv4_probe(void *packet, uint16_t packet_size,
        uint8_t dscp, int id, int ttl, uint16_t ident, struct addrinfo *dest);
int amp_traceroute_build_ipv6_probe(void *packet, uint16_t packet_size, int id,
        uint16_t ident, struct addrinfo *dest);
#endif


/* Used to describe responses */
typedef enum {
    REPLY_UNKNOWN = 0,
    REPLY_TIMED_OUT,
    REPLY_OK,
} reply_t;

/*
 * Packet structure used in the body of IPv6 packets, it's easier to do it
 * this way than to create and send an entire packet ourselves.
 */
struct ipv6_body_t {
    uint16_t index;
    uint16_t ident;
};

/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    int random;			/* use random packet sizes (bytes) */
    int perturbate;		/* delay sending by up to this time (usec) */
    int ip;                     /* report the IP address of each hop */
    int as;                     /* lookup the AS number of each address */
    uint16_t packet_size;	/* use this packet size (bytes) */
    uint32_t inter_packet_delay;/* minimum gap between packets (usec) */
    uint8_t dscp;
};

/*
 * Information block for the probe sent to a particular TTL.
 */
struct hop_info_t {
    struct timeval time_sent;	/* when the probe was sent */
    int64_t as;                 /* AS that the address belongs to */
    uint32_t delay;		/* delay in receiving response, microseconds */
    reply_t reply;              /* Has a reply been received */
    struct addrinfo *addr;      /* Address that the reply came from */
};

/*
 * Information block recording data for the UDP probe packets sent to a single
 * destination.
 */
typedef struct dest_info_t dest_info_t;
struct dest_info_t {
    struct addrinfo *addr;      /* address probe was sent to */
    uint32_t id;                /* ID number of destination */
    uint32_t probes;            /* number of probes sent so far */
    int8_t first_response;      /* TTL of first response packet */
    int8_t ttl;                 /* current TTL being probed */
    int8_t first_ttl;           /* initial TTL that was probed */
    uint8_t path_length;        /* total length of path, once confirmed */
    uint8_t done_forward;       /* true if forward probing has finished */
    uint8_t attempts;           /* number of probe attempts at this TTL */
    uint8_t no_reply_count;     /* number of probes sent without response */
    uint8_t err_type;           /* ICMP response error type (0 if success) */
    uint8_t err_code;           /* ICMP response error code */
    struct hop_info_t hop[MAX_HOPS_IN_PATH];
    struct dest_info_t *next;
};

/*
 * Lists of targets that are yet to be probed, being probed, or completed
 * probing, along with all the associated timers and metadata used to keep
 * track of where we are up to.
 */
struct probe_list_t {
    struct socket_t *sockets;
    struct dest_info_t *pending;        /* targets yet to be probed */
    struct dest_info_t *ready;          /* targets ready to be probed */
    struct dest_info_t *ready_end;
    struct dest_info_t *outstanding;    /* targets with an outstanding probe */
    struct dest_info_t *outstanding_end;
    struct dest_info_t *done;           /* targets with completed paths */
    struct wand_timer_t *timeout;
    struct wand_timer_t *sendtimer;
    uint32_t count;
    uint32_t done_count;
    uint16_t ident;
    struct opt_t *opts;
    int total_probes;
    struct timeval *last_probe;	        /* when most recent probe was sent */
};

#endif
