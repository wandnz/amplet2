/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2019 The University of Waikato, Hamilton, New Zealand.
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

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "external.h"
#include "external.pb-c.h"



struct opt_t {
    char *target;
    char *command;
    int64_t value;
};



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(char *command, Amplet2__External__Header *header) {
    assert(header->command);
    assert(strcmp(command, header->command) == 0);
}



/*
 *
 */
static void verify_response(char *name, int64_t *value,
        Amplet2__External__Item *item) {

    if ( value ) {
        assert(item->has_value);
        assert(*value == item->value);
    } else {
        assert(!item->has_value);
    }

    if ( name ) {
        assert(strcmp(name, item->name) == 0);
    } else {
        assert(item->name == NULL);
    }
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(char *name, char *command, int64_t *value,
        amp_test_result_t *result) {

    Amplet2__External__Report *msg;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__external__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == 1);

    verify_header(command, msg->header);

    /* check each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        verify_response(name, value, msg->reports[i]);
    }

    amplet2__external__report__free_unpacked(msg, NULL);
}



/*
 *
 */
int main(void) {
    int count, i;
    struct timeval start_time = {1, 0};

    struct opt_t options[] = {
        {NULL, "command", 0},
        {NULL, "command", -1},
        {NULL, "command", 1},
        {"foo.example.com", "a", 0},
        {"bar.example.com", "b", -(1<<15)},
        {"baz.example.com", "c", 1<<15},
        {"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z", "a", 0},
        {"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z", "a", -(1<<16)},
        {"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z", "a", 1<<16},
        {"a", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 0},
        {"b", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",-(1L<<31)},
        {"c", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 1L << 31},
        {"d", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",-(1L<<32)},
        {"e", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 1L << 32},
        {"f", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",-(1L<<62)},
        {"g", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 1L << 62},
    };

    count = sizeof(options) / sizeof(struct opt_t);
    for ( i = 0; i < count; i++ ) {
        char *target = options[i].target;
        char *command = options[i].command;
        int64_t value = options[i].value;

        verify_message(target, command, &value,
                amp_test_report_results(&start_time, target, command, &value));
    }

    /* try a NULL value too */
    verify_message(NULL, "command", NULL,
            amp_test_report_results(&start_time, NULL, "command", NULL));

    return 0;
}
