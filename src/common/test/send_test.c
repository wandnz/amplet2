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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include "testlib.h"

#define TEST_PACKETS 10000
#define MAX_PACKET_LEN 512


/*
 * Check that packets are being sent correctly and that the delay between
 * sending them is being enforced properly.
 *
 * To do that we are just doing an average speed check - send all the packets
 * and make sure that it takes at least as long as the number of packets
 * multiplied by the minimum inter-packet wait time. If the machine is heavily
 * loaded then this check becomes less useful, but I think it's still
 * worthwhile.
 */
int main(void) {
    struct addrinfo dest;
    int sockets[2];
    char out_packet[MAX_PACKET_LEN];
    char in_packet[MAX_PACKET_LEN];
    int delay, length, i;
    struct timeval start, end;
    int64_t duration;

    /*
     * use a pair of unix sockets to test sending data without relying on
     * the network being present/sane/etc.
     */
    if ( socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0 ) {
        fprintf(stderr, "Failed to create socket pair: %s\n", strerror(errno));
        return -1;
    }

    /* we don't need a real address for testing, our socket pair is connected */
    dest.ai_addr = NULL;
    dest.ai_addrlen = 0;

    gettimeofday(&start, NULL);

    for ( i = 0; i < TEST_PACKETS; i++ ) {
        /* fill the packet with some data we can check later */
        length = i % MAX_PACKET_LEN;
        out_packet[length++] = i % 255;

        /* loop until the packet is allowed to be sent or errors */
        while ( (delay = delay_send_packet(sockets[0], out_packet, length,
                        &dest, MIN_INTER_PACKET_DELAY, NULL)) > 0 ) {
            assert(delay <= MIN_INTER_PACKET_DELAY);
            usleep(delay);
        }

        if ( delay < 0 ) {
            fprintf(stderr, "Failed to send packet: %s\n", strerror(errno));
            return -1;
        }

        /* try to read the packet that we just sent */
        if ( recv(sockets[1], in_packet, MAX_PACKET_LEN, 0) != length ) {
            fprintf(stderr, "Failed to receive packet: %s\n", strerror(errno));
            return -1;
        }

        /* confirm that it matches what we sent */
        assert(memcmp(out_packet, in_packet, length) == 0);
    }

    gettimeofday(&end, NULL);

    /* check that we took longer than the minimum possible time */
    duration = DIFF_TV_US(end, start);
    assert(duration > (TEST_PACKETS * MIN_INTER_PACKET_DELAY));

    close(sockets[0]);
    close(sockets[1]);

    return 0;
}
