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

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "testlib.h"

/*
 * Test binding a socket to a particular address.
 */
int main(void) {
    int sock;
    socklen_t addrlen;
    struct addrinfo *address, hints;
    struct sockaddr_storage actual;
    char *addresses[] = {
        "127.0.0.1", "127.0.0.2", "127.0.0.3", "0.0.0.0",
        "::1", "::"
    };
    int count;
    int i;
    void *addr1, *addr2;
    int length;

    count = sizeof(addresses) / sizeof(char *);
    memset(&actual, 0, sizeof(actual));
    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    for ( i = 0; i < count; i++ ) {

        /* turn our address string into a more useful addrinfo struct */
        if ( getaddrinfo(addresses[i], NULL, &hints, &address) < 0 ) {
            fprintf(stderr, "Failed to get address info: %s\n",
                    strerror(errno));
            return -1;
        }

        /* create the socket */
        if ( (sock = socket(address->ai_family, SOCK_DGRAM, 0)) < 0 ) {
            fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
            return -1;
        }

        /* try to bind to the given address */
        if ( bind_socket_to_address(sock, address) < 0 ) {
            fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
            return -1;
        }

        /* get the address that the socket is actually bound to */
        addrlen = address->ai_addrlen;
        if ( getsockname(sock, (struct sockaddr*)&actual, &addrlen) < 0 ) {
            fprintf(stderr, "Failed to get socket info: %s\n", strerror(errno));
            return -1;
        }

        /* check that the bound socket matches what we were expecting */
        assert(addrlen == address->ai_addrlen);
        assert(address->ai_family == actual.ss_family);

        switch(address->ai_family) {
            case AF_INET:
                addr1 = &((struct sockaddr_in*)address->ai_addr)->sin_addr;
                addr2 = &((struct sockaddr_in*)&actual)->sin_addr;
                length = sizeof(struct in_addr);
                break;
            case AF_INET6:
                addr1 = &((struct sockaddr_in6*)address->ai_addr)->sin6_addr;
                addr2 = &((struct sockaddr_in6*)&actual)->sin6_addr;
                length = sizeof(struct in6_addr);
                break;
            default:
                assert(0);
        };

        assert(memcmp(addr1, addr2, length) == 0);

        freeaddrinfo(address);
    }

    return 0;
}
