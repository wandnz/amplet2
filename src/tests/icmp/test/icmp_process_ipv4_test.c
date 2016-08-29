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
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <time.h>

#include "tests.h"
#include "icmp.h"

#define MAX_PACKET_LEN 512
#define MIN_VALID_LEN ( \
        sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(uint16_t) )
#define MIN_EMBEDDED_LEN ( \
        (2*sizeof(struct iphdr)) + (2*sizeof(struct icmphdr)) )

/*
 */
int main(void) {
    char packet[MAX_PACKET_LEN];
    struct icmpglobals_t globals;
    struct timeval now = {0, 0};
    struct iphdr *ip;
    struct icmphdr icmps[] = {
        /* good response */
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(1), 0}} },
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(123), htons(1)}} },
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(5678), htons(2)}} },

        /* good response, but too short */
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(5678), htons(3)}} },
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(5678), htons(4)}} },

        /* incorrect responses */
        { ICMP_ECHO, 0, 0, { .echo = {htons(5678), htons(5)}} },
        { NR_ICMP_TYPES+1, 0, 0, { .echo = {htons(5678), htons(6)}} },

        /* TODO incorrect responses with embedded packets */
        //{ ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0, { .echo = {0, 0} } },
    };
    unsigned int length[] = {
        /* good response responses */
        MIN_VALID_LEN,
        MIN_VALID_LEN,
        MIN_VALID_LEN,

        /* good response, but too short */
        sizeof(struct iphdr) + sizeof(struct icmphdr),
        sizeof(struct iphdr),

        /* incorrect responses */
        MIN_VALID_LEN,
        MIN_VALID_LEN,

        /* TODO incorrect responses with embedded packets */
        //MIN_EMBEDDED_LEN,
    };
    int results[] = { 0, 0, 0, -1, -1, -1, -1, /*0*/ };

    /* check our test settings and results match up */
    assert((sizeof(icmps) / sizeof(struct icmphdr)) ==
            (sizeof(results) / sizeof(int)));
    assert(sizeof(icmps) / sizeof(struct icmphdr) ==
            (sizeof(length) / sizeof(int)));

    globals.count = sizeof(icmps) / sizeof(struct icmphdr);

    globals.info = (struct info_t *)malloc(sizeof(struct info_t)*globals.count);
    memset(globals.info, 0, sizeof(struct info_t) * globals.count);
    memset(packet, 0, sizeof(packet));

    /* TODO change the IP header length in some tests? */
    ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;

    srand(time(NULL));

    for ( globals.index = 0; globals.index < globals.count; globals.index++ ) {
        globals.info[globals.index].magic = rand();
        ip->tot_len = length[globals.index];
        globals.ident = ntohs(icmps[globals.index].un.echo.id);

        /* fill the packet with each icmp header and magic in turn */
        memcpy(packet + sizeof(struct iphdr),
                &icmps[globals.index], sizeof(struct icmphdr));
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr),
                &globals.info[globals.index].magic,
                sizeof(globals.info[globals.index].magic));

        /* check that it passed or failed appropriately */
        assert(amp_test_process_ipv4_packet(&globals, packet,
                    length[globals.index], &now) == results[globals.index]);

        /*
         * The error type/code will only be set if it can be determined to be a
         * response to a probe packet that we sent. If it's too short or too
         * wrong, then this won't be set.
         */
        if ( icmps[globals.index].type < NR_ICMP_TYPES &&
                icmps[globals.index].type != ICMP_ECHO &&
                length[globals.index] >= MIN_VALID_LEN ) {
            assert(globals.info[globals.index].err_type ==
                    icmps[globals.index].type);
            assert(globals.info[globals.index].err_code ==
                    icmps[globals.index].code);
        }
    }

    free(globals.info);

    return 0;
}
