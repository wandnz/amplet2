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

#include "config.h"

#ifndef HAVE_LIBEVENT_FOREACH

#include <event2/event.h>
#include "libevent_internal.h"

/*
 * The function event_base_foreach_event() is only available from libevent
 * version 2.1 onwards, so implement our own version of it here for use with
 * version 2.0.21. Very loosely based on event_base_dump_events() from
 * https://github.com/libevent/libevent/blob/release-2.0.21-stable/event.c
 * except it calls an arbitrary function and actually includes timer events.
 *
 * In theory (!) we shouldn't need to worry about locking as this is all run
 * in a single thread.
 *
 * Currently required to support Xenial, Jessie, Stretch and Centos 7.
 */
int event_base_foreach_event(struct event_base *base,
    event_base_foreach_event_cb fn, void *arg) {

    struct event *e;
    int i;
    int r;

    if ( (!fn) || (!base) ) {
        return -1;
    }

    /* inserted events */
    TAILQ_FOREACH(e, &base->eventqueue, ev_next) {
        r = fn(base, e, arg);
        if ( r ) {
            return r;
        }
    }

    /* active events */
    for (i = 0; i < base->nactivequeues; ++i) {
        if (TAILQ_EMPTY(&base->activequeues[i]))
            continue;
        TAILQ_FOREACH(e, &base->eventqueue, ev_next) {
            r = fn(base, e, arg);
            if ( r ) {
                return r;
            }
        }
    }

    /* some timer events */
    for (i = 0; i < base->n_common_timeouts; ++i) {
        if (TAILQ_EMPTY(&base->common_timeout_queues[i]->events))
            continue;
        TAILQ_FOREACH(e, &base->common_timeout_queues[i]->events, ev_next) {
            r = fn(base, e, arg);
            if ( r ) {
                return r;
            }
        }
    }

    /* and the rest of the timer events */
    for (i = 0; i < (int)base->timeheap.n; i++) {
        r = fn(base, base->timeheap.p[i], arg);
        if ( r ) {
            return r;
        }
    }

    return 0;
}

#endif
