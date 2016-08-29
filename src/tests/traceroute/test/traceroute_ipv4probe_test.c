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
#define DSCP_COUNT (sizeof(dscps) / sizeof(uint8_t))
#define IDENT_COUNT (sizeof(idents) / sizeof(uint16_t))
#define SIZE_COUNT (sizeof(packet_sizes) / sizeof(int))
#define DEST_COUNT (sizeof(dests) / sizeof(uint32_t))

/*
 * Check that the individual members of the IPv4 and UDP headers were actually
 * set to the values that were given.
 */
static void check_ipv4_probe(void *packet, uint16_t size, uint8_t dscp, int id,
        int ttl, uint16_t ident, struct addrinfo *dest) {

    struct iphdr *ip;
    struct udphdr *udp;

    /* check that the IPv4 header is set correctly */
    ip = (struct iphdr *)packet;
    assert(ip->version == 4);
    assert(ip->ihl == 5);
    assert(IPTOS_DSCP(ip->tos) == dscp);
    assert(ntohs(ip->tot_len) == size);
    assert(ntohs(ip->id) == id);
    assert(ip->ttl == ttl);
    assert(ip->protocol == IPPROTO_UDP);
    assert(ip->daddr == ((struct sockaddr_in *)dest->ai_addr)->sin_addr.s_addr);

    /* check that the UDP header is set correctly */
    udp = (struct udphdr *)((uint8_t *)packet + (ip->ihl << 2));
    assert(ntohs(udp->source) == ident);
    assert(ntohs(udp->dest) == TRACEROUTE_DEST_PORT);
    assert(ntohs(udp->len) == (size - ((ip->ihl << 2))));
}

/*
 * Check that the traceroute test builds sane IPv4 probe packets.
 */
int main(void) {
    char packet[MAXLEN];
    uint16_t id, ttl, dscp, size, ident, dest, coded_id;
    struct addrinfo addr;
    int length;

    /* id is incremented by one for every destination site */
    int ids[] = {0, 1, 2, 3, 4, 8, 16, 32};

    /* ttl is incremented by one until destination responds */
    int ttls[] = {1, 2, 3, 4, 8, 16, MAX_HOPS_IN_PATH};

    /* DSCP values range from 0 to 63 (6 bits) */
    uint8_t dscps[] = {0, 8<<2, 10<<2, 16<<2, 20<<2, 38<<2, 46<<2, 56<<2,63<<2};

    /* all idents should be from 9001 to 65535 */
    uint16_t idents[] = {9001, 11111, 12345, 33333, 65535};

    /* 10.0.0.1, 192.168.11.22, 130.217.250.13, 8.8.8.8 */
    uint32_t dests[] = {0x0100000a, 0x160ba8c0, 0x0dfad982, 0x08080808};

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

    /* use the same data about each address, just change the actual address */
    addr.ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
    addr.ai_family = AF_INET;
    addr.ai_addrlen = sizeof(struct sockaddr_in);
    addr.ai_canonname = NULL;
    addr.ai_next = NULL;

    /* lets try every combination of values, there aren't that many */
    for ( id = 0; id < ID_COUNT; id++ ) {
    for ( ttl = 0; ttl < TTL_COUNT; ttl++ ) {
    for ( dscp = 0; dscp < DSCP_COUNT; dscp++ ) {
    for ( ident = 0; ident < IDENT_COUNT; ident++ ) {
    for ( size = 0; size < SIZE_COUNT; size++ ) {
    for ( dest = 0; dest < DEST_COUNT; dest++ ) {

        /* fill in the destination address */
        ((struct sockaddr_in *)addr.ai_addr)->sin_addr.s_addr = dests[dest];

        /* actual id in packet also includes ttl */
        coded_id = (ttls[ttl] << 10) + ids[id];

        /* construct the probe packet */
        length = amp_traceroute_build_ipv4_probe(packet, packet_sizes[size],
                dscps[dscp], coded_id, ttls[ttl], idents[ident], &addr);

        /* check the constructed probe packet */
        assert(length == packet_sizes[size]);
        check_ipv4_probe(packet, packet_sizes[size], dscps[dscp], coded_id,
                ttls[ttl], idents[ident], &addr);
    } } } } } }

    free(addr.ai_addr);

    return 0;
}
