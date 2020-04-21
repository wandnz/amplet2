/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * https://github.com/libevent/libevent/blob/release-2.0.21-stable/evsignal-internal.h
 * https://github.com/libevent/libevent/blob/release-2.0.21-stable/event-internal.h
 */

#ifndef _MEASURED_LIBEVENT_INTERNAL_H
#define _MEASURED_LIBEVENT_INTERNAL_H

#include "config.h"

#ifndef HAVE_LIBEVENT_FOREACH

#include <sys/queue.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include "libevent_minheap.h"

struct evsig_info {
    /* Event watching ev_signal_pair[1] */
    struct event ev_signal;
    /* Socketpair used to send notifications from the signal handler */
    evutil_socket_t ev_signal_pair[2];
    /* True iff we've added the ev_signal event yet. */
    int ev_signal_added;
    /* Count of the number of signals we're currently watching. */
    int ev_n_signals_added;

    /* Array of previous signal handler objects before Libevent started
     * messing with them.  Used to restore old signal handlers. */
#ifdef _EVENT_HAVE_SIGACTION
    struct sigaction **sh_old;
#else
    ev_sighandler_t **sh_old;
#endif
    /* Size of sh_old. */
    int sh_old_max;
};

struct event_signal_map {
    /* An array of evmap_io * or of evmap_signal *; empty entries are
     * set to NULL. */
    void **entries;
    /* The number of entries available in entries */
    int nentries;
};
#define event_io_map event_signal_map

struct event_changelist {
    void *changes;
    int n_changes;
    int changes_size;
};

struct deferred_cb_queue {
    /** Lock used to protect the queue. */
    void *lock;

    /** How many entries are in the queue? */
    int active_count;

    /** Function called when adding to the queue from another thread. */
    void (*notify_fn)(struct deferred_cb_queue *, void *);
    void *notify_arg;

    /** Deferred callback management: a list of deferred callbacks to
     * run active the active events. */
    TAILQ_HEAD (deferred_cb_list, deferred_cb) deferred_cb_list;
};

struct common_timeout_list {
    /* List of events currently waiting in the queue. */
    struct event_list events;
    /* 'magic' timeval used to indicate the duration of events in this
     * queue. */
    struct timeval duration;
    /* Event that triggers whenever one of the events in the queue is
     * ready to activate */
    struct event timeout_event;
    /* The event_base that this timeout list is part of */
    struct event_base *base;
};

/*
 * some of these unused pointer fields have been changed to void types to
 * avoid including their definitions
 */
struct event_base {
    void *evsel;
    void *evbase;
    struct event_changelist changelist;
    void *evsigsel;
    struct evsig_info sig;
    int virtual_event_count;
    int event_count;
    int event_count_active;
    int event_gotterm;
    int event_break;
    int event_continue;
    int event_running_priority;
    int running_loop;
    struct event_list *activequeues;
    int nactivequeues;
    struct common_timeout_list **common_timeout_queues;
    int n_common_timeouts;
    int n_common_timeouts_allocated;
    struct deferred_cb_queue defer_queue;
    struct event_io_map io;
    struct event_signal_map sigmap;
    struct event_list eventqueue;
    struct timeval event_tv;
    struct min_heap timeheap;
    /* plus extra fields after the bits we care about that aren't useful here */
};

typedef int (*event_base_foreach_event_cb)(const struct event_base *,
        const struct event *, void *);

int event_base_foreach_event(struct event_base *base,
    event_base_foreach_event_cb fn, void *arg);
#endif
#endif
