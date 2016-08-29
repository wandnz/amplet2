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
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include "testlib.h"

#define TEST_PACKETS 1000
#define MAX_PACKET_LEN 512

/*
 * Check that data is received correctly by get_packet() and that the correct
 * amount of data is received, on both ipv4 and ipv6 code paths.
 */
int main(void) {
    int sockets[2];
    struct socket_t amp_sockets;
    char out_packet[MAX_PACKET_LEN];
    char in_packet[MAX_PACKET_LEN];
    int maxwait, length, bytes, i;
    int sent = -1;

    /*
     * use a pair of unix sockets to test sending data without relying on
     * the network being present/sane/etc.
     */
    if ( socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0 ) {
        fprintf(stderr, "Failed to create socket pair: %s\n", strerror(errno));
        return -1;
    }

    /*
     * The code under test doesn't actually care about the address family
     * and will assume that "socket" is ipv4 and "socket6" is ipv6.
     */
    amp_sockets.socket = sockets[0];
    amp_sockets.socket6 = sockets[1];

    for ( i = 0; i < TEST_PACKETS; i++ ) {
        /* fill the packet with some data we can check later */
        length = i % MAX_PACKET_LEN;
        out_packet[length++] = i % 255;
        maxwait = 1;

        switch ( i % 3 ) {
            case 0:
                /* send to the ipv4 socket, to trigger ipv6 as ready to read */
                sent = send(amp_sockets.socket, out_packet, length, 0);
                break;
            case 1:
                /* send to the ipv6 socket, to trigger ipv4 as ready to read */
                sent = send(amp_sockets.socket6, out_packet, length, 0);
                break;
            case 2:
                /* no data has been written, it should timeout */
                sent = 0;
                break;
        };

        /*
         * There might be some sizing issues with get_packet() setting addrlen
         * internally to the sizeof a sockaddr_in or sockaddr_in6, but that\
         * will just truncate the address returned by recvfrom(), something we
         * aren't looking at.
         */
        bytes = get_packet(&amp_sockets, in_packet, MAX_PACKET_LEN, NULL,
                &maxwait, NULL);

        assert(bytes == sent);

        if ( bytes > 0 ) {
            /* confirm that it matches what we sent */
            assert(memcmp(out_packet, in_packet, bytes) == 0);
        }
    }

    close(sockets[0]);
    close(sockets[1]);

    return 0;
}
