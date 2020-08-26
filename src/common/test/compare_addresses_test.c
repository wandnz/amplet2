/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
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
#include <netdb.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "testlib.h"

struct test_compare {
    char *a;
    char *b;
    int prefix;
    int expected;
};



/*
 * Test that the prefix aware address comparison function works correctly.
 */
int main(void) {
    int i;
    int count;
    int result;
    struct addrinfo hints;
    struct test_compare comp[] = {
        {"127.0.0.1", "127.0.0.1", 0, 0},
        {"127.0.0.1", "127.0.0.1", 8, 0},
        {"127.0.0.1", "127.0.0.1", 16, 0},
        {"127.0.0.1", "127.0.0.1", 24, 0},
        {"127.0.0.1", "127.0.0.1", 32, 0},

        {"127.0.0.1", "127.0.0.2", 0, 0},
        {"127.0.0.1", "127.0.0.2", 8, 0},
        {"127.0.0.1", "127.0.0.2", 16, 0},
        {"127.0.0.1", "127.0.0.2", 24, 0},
        {"127.0.0.1", "127.0.0.2", 30, 0},
        {"127.0.0.1", "127.0.0.2", 31, -1},
        {"127.0.0.1", "127.0.0.2", 32, -1},

        {"127.0.0.1", "128.0.0.1", 0, 0},
        {"127.0.0.1", "128.0.0.1", 1, -1},
        {"127.0.0.1", "128.0.0.1", 8, -1},
        {"127.0.0.1", "128.0.0.1", 16, -1},
        {"127.0.0.1", "128.0.0.1", 24, -1},
        {"127.0.0.1", "128.0.0.1", 32, -1},

        {"192.168.0.0", "192.168.0.1", 0, 0},
        {"192.168.0.0", "192.168.0.1", 8, 0},
        {"192.168.0.0", "192.168.0.1", 16, 0},
        {"192.168.0.0", "192.168.0.1", 24, 0},
        {"192.168.0.0", "192.168.0.1", 31, 0},
        {"192.168.0.0", "192.168.0.1", 32, -1},

        {"192.168.0.0", "192.168.0.128", 0, 0},
        {"192.168.0.0", "192.168.0.128", 8, 0},
        {"192.168.0.0", "192.168.0.128", 16, 0},
        {"192.168.0.0", "192.168.0.128", 24, 0},
        {"192.168.0.0", "192.168.0.128", 25, -1},
        {"192.168.0.0", "192.168.0.128", 32, -1},

        {"172.16.255.255", "172.16.0.255", 0, 0},
        {"172.16.255.255", "172.16.0.255", 8, 0},
        {"172.16.255.255", "172.16.0.255", 16, 0},
        {"172.16.255.255", "172.16.0.255", 17, 1},
        {"172.16.255.255", "172.16.0.255", 24, 1},
        {"172.16.255.255", "172.16.0.255", 32, 1},

        {"10.127.0.0", "10.128.0.0", 0, 0},
        {"10.127.0.0", "10.128.0.0", 8, 0},
        {"10.127.0.0", "10.128.0.0", 9, -1},
        {"10.127.0.0", "10.128.0.0", 16, -1},
        {"10.127.0.0", "10.128.0.0", 24, -1},
        {"10.127.0.0", "10.128.0.0", 32, -1},

        {"::1", "::1", 0, 0},
        {"::1", "::1", 32, 0},
        {"::1", "::1", 64, 0},
        {"::1", "::1", 96, 0},
        {"::1", "::1", 128, 0},

        {"2001:db8::1", "2001:db8::2", 0, 0},
        {"2001:db8::1", "2001:db8::2", 32, 0},
        {"2001:db8::1", "2001:db8::2", 64, 0},
        {"2001:db8::1", "2001:db8::2", 96, 0},
        {"2001:db8::1", "2001:db8::2", 126, 0},
        {"2001:db8::1", "2001:db8::2", 127, -1},
        {"2001:db8::1", "2001:db8::2", 128, -1},

        {"2001:db8:ffff::1", "2001:db8::2", 0, 0},
        {"2001:db8:ffff::1", "2001:db8::2", 32, 0},
        {"2001:db8:ffff::1", "2001:db8::2", 33, 1},
        {"2001:db8:ffff::1", "2001:db8::2", 64, 1},
        {"2001:db8:ffff::1", "2001:db8::2", 96, 1},
        {"2001:db8:ffff::1", "2001:db8::2", 128, 1},

        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 0, 0},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 32, 0},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 48, 0},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 49, 0},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 50, -1},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 64, -1},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 96, -1},
        {"2001:db8:ffff:8000::1", "2001:db8:ffff:c000::2", 128, -1},
    };

    count = sizeof(comp) / sizeof(struct test_compare);

    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;

    for ( i = 0; i < count; i++ ) {
        struct addrinfo *a, *b;

        /* turn our address strings into a addrinfo structs */
        if ( getaddrinfo(comp[i].a, NULL, &hints, &a) < 0 ) {
            fprintf(stderr, "Failed to get address info for %s\n", comp[i].a);
            return -1;
        }

        if ( getaddrinfo(comp[i].b, NULL, &hints, &b) < 0 ) {
            fprintf(stderr, "Failed to get address info for %s\n", comp[i].b);
            return -1;
        }

        result = compare_addresses(a->ai_addr, b->ai_addr, comp[i].prefix);
        if ( (comp[i].expected < 0 && result >= 0) ||
                (comp[i].expected > 0 && result <= 0) ||
                (comp[i].expected == 0 && result != 0) ) {
            fprintf(stderr, "Incorrect comparison %s/%d vs %s/%d\n",
                    comp[i].a, comp[i].prefix, comp[i].b, comp[i].prefix);
            fprintf(stderr, "Got:%d Expected: %d\n", result, comp[i].expected);
            return -1;
        }

        freeaddrinfo(a);
        freeaddrinfo(b);
    }

    return 0;
}
