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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "tests.h"
#include "traceroute.h"

#define MAXLEN 9000
#define ID_COUNT (sizeof(ids) / sizeof(int))
#define TTL_COUNT (sizeof(ttls) / sizeof(int))
#define IDENT_COUNT (sizeof(idents) / sizeof(uint16_t))
#define SIZE_COUNT (sizeof(packet_sizes) / sizeof(int))

/*
 * Check that the body of the IPv6 packet is built correctly. We rely on
 * the operating system to construct the rest of the packet for us (IPv6/UDP
 * headers etc).
 */
static void check_ipv6_probe(void *packet, int id, uint16_t ident,
        struct addrinfo *dest) {

    struct ipv6_body_t *ipv6_body;

    ipv6_body = (struct ipv6_body_t *)packet;
    assert(ntohs(ipv6_body->index) == id);
    assert(ntohs(ipv6_body->ident) == ident);
    assert(ntohs(((struct sockaddr_in6 *)dest->ai_addr)->sin6_port) ==
            TRACEROUTE_DEST_PORT);
}

/*
 * Check that the traceroute test builds sane IPv6 probe packets.
 */
int main(void) {
    char packet[MAXLEN];
    uint16_t id, ttl, size, ident, coded_id;
    struct addrinfo addr;
    int length;

    /* id is incremented by one for every destination site */
    int ids[] = {0, 1, 2, 3, 4, 8, 16, 32};

    /* ttl is incremented by one until destination responds */
    int ttls[] = {1, 2, 3, 4, 8, 16, MAX_HOPS_IN_PATH};

    /* all idents should be from 9001 to 65535 */
    uint16_t idents[] = {9001, 11111, 12345, 33333, 65535};

    /* packet size is usually default, but it can be changed */
    int packet_sizes[] = {
        MIN_TRACEROUTE_PROBE_LEN,
        DEFAULT_TRACEROUTE_PROBE_LEN,
        256,
        512,
        1024,
        1472,
        MAXLEN,
    };

    /* make sure we have some storage for our fake address */
    memset(&addr, 0, sizeof(addr));
    addr.ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in6));
    addr.ai_family = AF_INET6;
    addr.ai_addrlen = sizeof(struct sockaddr_in6);
    addr.ai_canonname = NULL;
    addr.ai_next = NULL;

    /* lets try every combination of values, there aren't that many */
    for ( id = 0; id < ID_COUNT; id++ ) {
        for ( ttl = 0; ttl < TTL_COUNT; ttl++ ) {
            for ( ident = 0; ident < IDENT_COUNT; ident++ ) {
                for ( size = 0; size < SIZE_COUNT; size++ ) {

                    /* actual id in packet also includes ttl */
                    coded_id = (ttls[ttl] << 10) + ids[id];

                    /* construct the probe packet */
                    length = amp_traceroute_build_ipv6_probe(packet,
                            packet_sizes[size], coded_id, idents[ident], &addr);

                    /* check the constructed probe packet */
                    assert(length == packet_sizes[size]);
                    check_ipv6_probe(packet, coded_id, idents[ident], &addr);
                }
            }
        }
    }

    free(addr.ai_addr);

    return 0;
}
