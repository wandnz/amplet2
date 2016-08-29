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
#include "tests.h"
#include "dns.h"

/*
 * Check that decoding names gives the correct results. Names should be decoded
 * according to section 4.1.4 of http://www.ietf.org/rfc/rfc1035.txt.
 */
int main(void) {
    int i;
    int count;
    char *name;

    /*
     * Some basic examples of encoded names, some without compression and
     * others having varying levels of redirection.
     */
    char *queries[] = {
        "\x03www\x07""example\x03org",
        "\x03""foo\x03""bar\x03""baz\x07""example\x03org",
        "\x01""a\x02""bb\x03""ccc\04""dddd\x07""example\x03org",
        "\x03www\x04wand\x03net\x02nz",
        "\x07skeptic\x04wand\x03net\x02nz",
        "\x07waikato\x03""amp\x04wand\x03net\x02nz",
        "\x1a""abcdefghijklmnopqrstuvwxyz\x07""example\x03org",
        "\x03www\x07""example\x03org\x00\03foo\xc0\x04\x00",
        "\x03www\x07""example\x03org\x00\03""bar\xc0\x04\x00\x03""foo\xc0\x11",
    };

    /* known correct decodings for the above names */
    char *responses[] = {
        "www.example.org",
        "foo.bar.baz.example.org",
        "a.bb.ccc.dddd.example.org",
        "www.wand.net.nz",
        "skeptic.wand.net.nz",
        "waikato.amp.wand.net.nz",
        "abcdefghijklmnopqrstuvwxyz.example.org",
        "foo.example.org",
        "foo.bar.example.org",
    };

    /* if compression is used, offset to the start of the name we want */
    int offsets[] = { 0, 0, 0, 0, 0, 0, 0, 17, 24};

    name = malloc(MAX_DNS_NAME_LEN * sizeof(char));
    memset(name, 0, MAX_DNS_NAME_LEN * sizeof(char));

    assert(sizeof(queries) == sizeof(responses));
    assert(sizeof(queries) / sizeof(char*) == sizeof(offsets) / sizeof(int));

    count = sizeof(queries) / sizeof(char*);
    for ( i = 0; i < count; i++ ) {
        amp_test_dns_decode(name, queries[i], queries[i] + offsets[i]);
        assert(strcmp(name, responses[i]) == 0);
    }

    free(name);

    return 0;
}
