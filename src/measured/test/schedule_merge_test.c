/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2022 The University of Waikato, Hamilton, New Zealand.
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
#include "schedule.h"
#include "run.h"


char *fixed_targets[] = {
    "a.example.com",
    "b.example.com",
    "c.example.com",
    "d.example.com",
    "e.example.com",
    "f.example.com",
};

char *resolve_targets[] = {
    "g.example.com",
    "h.example.com",
    "i.example.com",
    "j.example.com",
    "k.example.com",
    "l.example.com",
};



/*
 * Doesn't need a real test module, just needs a consistent block of memory.
 */
static test_t *new_test_module(void) {
    test_t *module = calloc(1, sizeof(test_t));
    return module;
}



static test_schedule_item_t *new_test(test_t *module, int start) {
    resolve_dest_t *dest1, *dest2;
    test_schedule_item_t *test;

    static int fixed_target = 0;
    static int resolve_target = 0;

    test = calloc(1, sizeof(test_schedule_item_t));
    test->start = start;
    test->test = module;

    /* already resolved dests are an array of pointers to addrinfo */
    test->dests = calloc(2, sizeof(struct addrinfo*));
    test->dests[0] = calloc(1, sizeof(struct addrinfo));
    test->dests[0]->ai_canonname = fixed_targets[fixed_target++];
    test->dests[1] = calloc(1, sizeof(struct addrinfo));
    test->dests[1]->ai_canonname = fixed_targets[fixed_target++];
    test->dest_count += 2;

    /* destinations to be resolved are a list of resolve_dest_t */
    dest1 = calloc(1, sizeof(resolve_dest_t));
    dest2 = calloc(1, sizeof(resolve_dest_t));
    dest1->name = resolve_targets[resolve_target++];
    dest1->next = dest2;
    dest2->name = resolve_targets[resolve_target++];
    dest2->next = NULL;

    test->resolve = dest1;
    test->resolve_count += 2;

    return test;
}



static schedule_item_t *new_schedule(struct event_base *base,
        test_schedule_item_t *test) {
    schedule_item_t *schedule = calloc(1, sizeof(schedule_item_t));
    schedule->type = EVENT_RUN_TEST;
    schedule->data.test = test;
    schedule->base = base;
    schedule->event = event_new(base, 0, EV_READ, run_scheduled_test, schedule);
    return schedule;
}



static int check_destinations(
        __attribute__((unused))const struct event_base *base,
        const struct event *ev,
        __attribute__((unused))void *evdata) {

    schedule_item_t *schedule;
    test_schedule_item_t *test;
    uint32_t i;
    resolve_dest_t *tmp;

    schedule = event_get_callback_arg(ev);
    test = schedule->data.test;

    /* use start time to differentiate the different tests */
    switch ( test->start ) {
        case 0:
            assert(test->dest_count == 2);
            assert(test->resolve_count == 2);
            assert(strcmp(test->dests[0]->ai_canonname, fixed_targets[0]) == 0);
            assert(strcmp(test->dests[1]->ai_canonname, fixed_targets[1]) == 0);
            for ( tmp = test->resolve, i = 0;
                    tmp != NULL;
                    tmp = tmp->next, i++ ) {
                assert(strcmp(tmp->name, resolve_targets[i]) == 0);
            }
            assert(i == 2);
            break;

        case 1:
            assert(test->dest_count == 4);
            assert(test->resolve_count == 4);
            assert(test->dests[0]->ai_canonname == fixed_targets[2]);
            assert(test->dests[1]->ai_canonname == fixed_targets[3]);
            assert(test->dests[2]->ai_canonname == fixed_targets[4]);
            assert(test->dests[3]->ai_canonname == fixed_targets[5]);

            for ( tmp = test->resolve, i = 2;
                    tmp != NULL;
                    tmp = tmp->next, i++ ) {
                assert(strcmp(tmp->name, resolve_targets[i]) == 0);
            }
            assert(i == 6);
            break;
    };

    return 0;
}



/*
 * Test the test argument parsing.
 */
int main(void) {
    struct event_base *base;
    const char *event_noepoll = "1";
    test_schedule_item_t *test0, *test1a, *test1b;
    schedule_item_t *schedule;
    test_t *module;

    module = new_test_module();

    assert(setenv("EVENT_NOEPOLL", event_noepoll, 0) == 0);

    base = event_base_new();
    assert(base);

    /* single test, can't merge */
    test0 = new_test(module, 0);
    assert(!amp_test_merge_scheduled_tests(base, test0));
    schedule = new_schedule(base, test0);
    event_add(schedule->event, NULL);

    /* add a second test, different attributes, can't merge */
    test1a = new_test(module, 1);
    assert(!amp_test_merge_scheduled_tests(base, test1a));
    schedule = new_schedule(base, test1a);
    event_add(schedule->event, NULL);

    /* add a third test, same attributes as second test, can merge */
    test1b = new_test(module, 1);
    assert(amp_test_merge_scheduled_tests(base, test1b));

    /* check that the destinations are as expected */
    event_base_foreach_event(base, check_destinations, NULL);

    return 0;
}
