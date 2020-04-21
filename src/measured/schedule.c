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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <assert.h>
#include <glob.h>
#include <curl/curl.h>
#include <yaml.h>
#include <stdint.h>
#include <inttypes.h>
#include <event2/event.h>

#include "config.h"
#include "schedule.h"
#include "watchdog.h"
#include "run.h"
#include "nametable.h"
#include "debug.h"
#include "modules.h"
#include "testlib.h"

#ifndef HAVE_LIBEVENT_FOREACH
#include "libevent_internal.h"
#endif



/*
 * Forward declear to use as function pointer values
 */
static void timer_fetch_callback(
        __attribute__((unused))evutil_socket_t evsock, 
        __attribute__((unused))short flags, 
        void *evdata);
int check_test_compare_callback(
         __attribute__((unused))const struct event_base *base, 
        const struct event *ev, 
        void *evdata);


/*
 * Dump a debug information line about a scheduled test.
 */
static void dump_event_run_test(test_schedule_item_t *item, FILE *out) {

    assert(item);

    fprintf(out, "EVENT_RUN_TEST ");
    fprintf(out, "%s %d.%.6d", item->test->name,
            (int)item->interval.tv_sec, (int)item->interval.tv_usec);

    if ( item->params == NULL ) {
        fprintf(out, " (no args)");
    } else {
        int i;
        /* params is a NULL terminated array */
        for ( i=0; item->params[i] != NULL; i++ ) {
            fprintf(out, " %s", item->params[i]);
        }
    }
    fprintf(out, "\n");
}



/*
 * Dump a debug information line about a scheduled schedule update.
 */
static void dump_event_fetch_schedule(fetch_schedule_item_t *item, FILE *out) {
    assert(item);

    fprintf(out, "EVENT_FETCH_SCHEDULE %s\n", item->schedule_url);
}



static int dump_events_callback(
        __attribute__((unused)) const struct event_base *base,
        const struct event *ev,
        void *evdata){

    struct timeval tv;
    schedule_item_t *item;
    FILE *out = evdata;
    event_callback_fn cb = event_get_callback(ev);

    if ( cb == run_scheduled_test || cb == timer_fetch_callback ) {
        event_pending(ev,EV_TIMEOUT,&tv);

        fprintf(out, "%d.%.6d ", (int)tv.tv_sec, (int)tv.tv_usec);
        item = event_get_callback_arg(ev);
        switch ( item->type ) {
            case EVENT_RUN_TEST:
                dump_event_run_test(item->data.test, out);
                break;
            case EVENT_FETCH_SCHEDULE:
                dump_event_fetch_schedule(item->data.fetch, out);
                break;
            default: fprintf(out, "UNKNOWN\n");
        };
    }
    return 0;
}

/*
 * Dump the current schedule for debug purposes
 */
void dump_schedule(struct event_base *base, FILE *out) {
    struct timeval wall;
    assert(out);

    event_base_gettimeofday_cached(base, &wall);

    fprintf(out, "===== SCHEDULE at %d.%d =====\n", (int)wall.tv_sec,
            (int)wall.tv_usec);

    event_base_foreach_event(base, dump_events_callback, out);

    fprintf(out, "\n");
}



/*
 * Free a test schedule item, as well as any parameters and pointers to
 * destinations it has.
 */
static void free_test_schedule_item(test_schedule_item_t *item) {

    if ( item == NULL ) {
        Log(LOG_WARNING, "Attempting to free NULL schedule item");
        return;
    }

    /* free any test parameters, NULL terminated array */
    if ( item->params != NULL ) {
        int i;
	for ( i=0; item->params[i] != NULL; i++ ) {
	    free(item->params[i]);
	}
	free(item->params);
    }
    /* free pointers to destinations, but not the destinations themselves */
    free(item->dests);

    /* free the list of names that need to be resolved at each test time */
    while ( item->resolve != NULL ) {
        resolve_dest_t *tmp = item->resolve;
        item->resolve = item->resolve->next;

        if ( tmp->name != NULL ) {
            free(tmp->name);
        }
        /* this should be NULL, it is only populated in a forked test */
        assert(tmp->addr == NULL);
        free(tmp);
    }

    free(item);
}



/*
 * Free the memory allocated for a "fetch schedule" schedule item.
 */
static void free_fetch_schedule_item(fetch_schedule_item_t *item) {

    if ( item == NULL ) {
        Log(LOG_WARNING, "Attempting to free NULL schedule item");
        return;
    }

    if ( item->schedule_url != NULL ) free(item->schedule_url);
    if ( item->schedule_dir != NULL ) free(item->schedule_dir);
    if ( item->cacert != NULL ) free(item->cacert);
    if ( item->cert != NULL ) free(item->cert);
    if ( item->key != NULL ) free(item->key);

    free(item);
}



/*
 * libevent can't operate on events while iterating over them, so instead
 * use a callback against every event to put them into our own list.
 */
struct tmp_event_list {
    struct event *event;
    struct tmp_event_list *next;
};



/*
 * Simple callback to add each event to a list of events.
 */
static int add_events_list_callback(
        __attribute__((unused)) const struct event_base *base,
        const struct event *ev,
        void *evdata) {
    /* prepend each event to the accumulating list */
    struct tmp_event_list **list = (struct tmp_event_list**)evdata;
    struct tmp_event_list *item = calloc(1, sizeof(struct tmp_event_list));
    item->event = (struct event*)ev;
    item->next = *list;
    *list = item;
    return 0;
}



/*
 * Walk the list of timers and remove all of them, or just those that are
 * scheduled tests. Refreshing the test schedule will still leave schedule
 * fetches in the list.
 */
void clear_test_schedule(struct event_base *base, int all) {
    struct tmp_event_list *list = NULL;

    /* can't make changes during foreach(), so first get all the events */
    event_base_foreach_event(base, add_events_list_callback, &list);

    /* and then unschedule the relevant events using event_free() */
    for ( struct tmp_event_list *current = list; current != NULL; /* */ ) {
        struct tmp_event_list *tmp;

        struct event *curr_event = current->event;
        event_callback_fn event_callback = event_get_callback(curr_event);
        schedule_item_t *item = event_get_callback_arg(curr_event);

        /*
         * Need to test the used callback to check what the event is, libevent
         * has some under the hood events that will also be listed here and we
         * cannot safely dereference 'item' until we know what it is
         */
        if ( event_callback != run_scheduled_test &&
                ( !all || event_callback != timer_fetch_callback )) {
            tmp = current;
            current = current->next;
            free(tmp);
            continue;
        }

        /* unschedule and free the event structure */
        event_free(curr_event);

        /* also free our own data that was attached to the event */
        switch ( item->type ) {
            case EVENT_RUN_TEST:
                if ( item->data.test != NULL ) {
                    free_test_schedule_item(item->data.test);
                }
                break;
            case EVENT_FETCH_SCHEDULE:
                if ( item->data.fetch != NULL ) {
                    free_fetch_schedule_item(item->data.fetch);
                }
                break;
            default:
                Log(LOG_WARNING, "Freeing unknown schedule item type %d",
                        item->type);
                break;
        };

        free(item);

        /* free each item in our temporary list as we walk it */
        tmp = current;
        current = current->next;
        free(tmp);
    }
}



/*
 * Convert a string from the schedule file into a regular time period.
 */
static schedule_period_t get_period_label(char *period) {
    if ( strcasecmp(period, "hour") == 0 || strcasecmp(period, "hourly") == 0 ||
            strcasecmp(period, "H") == 0 ) {
        return SCHEDULE_PERIOD_HOURLY;
    }

    if ( strcasecmp(period, "day") == 0 || strcasecmp(period, "daily") == 0 ||
            strcasecmp(period, "D") == 0 ) {
        return SCHEDULE_PERIOD_DAILY;
    }

    if ( strcasecmp(period, "week") == 0 || strcasecmp(period, "weekly") == 0 ||
            strcasecmp(period, "W") == 0 ) {
        return SCHEDULE_PERIOD_WEEKLY;
    }

    return SCHEDULE_PERIOD_INVALID;
}



/*
 * Convert the repeat period fromm the schedule to the number of seconds in
 * that repeat period.
 */
static time_t get_period_max_value(schedule_period_t period) {
    switch ( period ) {
	case SCHEDULE_PERIOD_HOURLY: return 60*60;
	case SCHEDULE_PERIOD_DAILY: return 60*60*24;
	case SCHEDULE_PERIOD_WEEKLY: return 60*60*24*7;
	default: return -1;
    };
}



/*
 * Get the default test frequency (in seconds) to use for a test if it isn't
 * specified, based on the test period.
 */
static time_t get_period_default_frequency(schedule_period_t period) {
    switch ( period ) {
	case SCHEDULE_PERIOD_HOURLY: return 60;
	case SCHEDULE_PERIOD_DAILY: return 60*10;
	case SCHEDULE_PERIOD_WEEKLY: return 60*60;
	default: return -1;
    };
}



/*
 * Make sure that the value (in microseconds) fits within the period.
 */
static int64_t check_time_range(int64_t value, schedule_period_t period) {
    int64_t max_interval;

    /* don't accept any value that would overflow the time period */
    max_interval = ((int64_t)get_period_max_value(period)) * 1000000;

    /* negative values are illegal, as are any outside of the repeat cycle */
    if ( max_interval < 0 || value < 0 || value > max_interval ) {
	return -1;
    }

    return value;
}



/*
 * Get the time in seconds for the beginning of the current period. timegm()
 * should deal with any wrap around for weekly periods.
 */
static time_t get_period_start(schedule_period_t period, time_t *now) {
    struct tm period_start;

    gmtime_r(now, &period_start);
    period_start.tm_sec = 0;
    period_start.tm_min = 0;

    switch ( period ) {
	case SCHEDULE_PERIOD_HOURLY: /* time is already start of hour */ break;
	case SCHEDULE_PERIOD_DAILY: period_start.tm_hour = 0; break;
	case SCHEDULE_PERIOD_WEEKLY: period_start.tm_hour = 0;
		  period_start.tm_mday -= period_start.tm_wday;
		  break;
	default: /* assume daily for now */ period_start.tm_hour = 0; break;
    };

    return timegm(&period_start);
}



/*
 * Peek ahead a character to make sure it isn't the null terminator.
 */
static int check_more_data(char *stream) {
    return ( *(stream + 1) != '\0' );
}



/*
 * Copy the current token and then zero the token ready for the next one.
 */
static void save_token(char *token, char **destination) {
    *destination = strdup(token);
    memset(token, 0, MAX_ARGUMENT_LENGTH);
}



/*
 * TODO do we need to check the parameters here, given they are going to be
 * used as part of the parameter array given to execv?
 */
/*
 * Ideally we would use some sort of command line parsing functions from the
 * standard library, but nothing seems to do what we want:
 *
 *   getopt():  operates on strings that have already been split.
 *   wordexp(): does too much work (variable substitution, path expansion) and
 *              possibly exposes parts of the system we'd rather not expose.
 *   flex:      seemed like it would be overkill for such a simple situation.
 *
 * So, instead we have this simple state machine. It accumulates valid
 * characters into a buffer as it reads through the string, ignoring escape
 * characters but adding the character that was escaped. Whitespace outside
 * of a pair of quotes creates a token from the accumulated buffer.
 */
char **parse_param_string(char *param_string) {
    int state = WHITESPACE;
    int count = 0;
    char **result;
    char *p;
    char token[MAX_ARGUMENT_LENGTH + 1] = {'\0'};
    int offset = 0;
    int i;

    if ( param_string == NULL || *param_string == '\0' ) {
        /* return a null element to show parsing was successful, but empty */
        result = calloc(1, sizeof(char*));
        return result;
    }

    /* TODO we can realloc this as we go */
    result = (char**)malloc(sizeof(char*) * MAX_TEST_ARGS);

    for ( p = param_string; *p != '\0'; p++ ) {
        switch ( state ) {
            /* keep consuming whitespace until we see a useful character */
            case WHITESPACE: {
                switch ( *p ) {
                    case '\\': {
                        /* ensure a character follows the escaping slash */
                        if ( !check_more_data(p) ) {
                            goto parse_param_error;
                        }
                        /* skip the slash character */
                        p++;
                        /* store the next character but don't inspect it */
                        token[offset++] = *p;
                        state = CHARACTER;
                    } break;
                    case '\n':
                    case ' ':
                    case '\t': break;
                    case '"': state = DQUOTE; break;
                    case '\'': state = SQUOTE; break;
                    default:
                        token[offset++] = *p;
                        state = CHARACTER;
                        break;
                };
            } break;

            /* keep consuming characters until we see the matching end quote */
            case DQUOTE:
            case SQUOTE: {
                if ( (state == DQUOTE && *p == '"') ||
                        (state == SQUOTE && *p == '\'') ) {
                    state = CHARACTER;
                    break;
                }

                if ( *p == '\\' ) {
                    if ( !check_more_data(p) ) {
                        goto parse_param_error;
                    }
                    p++;
                }

                token[offset++] = *p;
            } break;

            /* keep consuming characters until we see a quote or whitespace */
            case CHARACTER: {
                switch ( *p ) {
                    case '\\': {
                        if ( !check_more_data(p) ) {
                            goto parse_param_error;
                        }
                        p++;
                        token[offset++] = *p;
                    } break;
                    case '"': state = DQUOTE; break;
                    case '\'': state = SQUOTE; break;
                    case '\n':
                    case ' ':
                    case '\t': {
                        save_token(token, &result[count++]);
                        offset = 0;
                        state = WHITESPACE;
                    } break;
                    default: token[offset++] = *p; break;
                };
            } break;
        };
    }

    /* it's an error to have an open set of quotes when we run out of input */
    if ( state == DQUOTE || state == SQUOTE ) {
        goto parse_param_error;
    }

    /* otherwise finish up the last token that was built when input ran out */
    save_token(token, &result[count++]);

    /* param list should be null terminated */
    result[count] = NULL;

    return result;

parse_param_error:
    for ( i = 0; i < count; i++ ) {
        free(result[i]);
    }
    free(result);
    return NULL;
}



/*
 * Calculate the next time that a test is due to be run and return a timeval
 * with an offset appropriate for use with libevent scheduling. We have to
 * use an offset because libevent schedules relative to a monotonic clock,
 * not the system clock.
 */
static inline struct timeval get_next_schedule_time_internal(
        struct timeval *now, schedule_period_t period, uint64_t start, 
        uint64_t end, uint64_t frequency, int run, struct timeval *abstime) {

    time_t period_start, period_end;
    struct timeval next = {0,0};
    int64_t diff, test_end;
    int next_repeat;

    period_start = get_period_start(period, &now->tv_sec);
    test_end = (period_start * INT64_C(1000000)) + end;

    /* get difference in us between the first event of this period and now */
    diff = now->tv_sec - period_start;
    diff *= 1000000;
    diff += now->tv_usec;
    diff -= start;

    /* if the difference is negative, we are before the first scheduled run */
    if ( diff < 0 ) {
        /*
         * Make sure that if we just ran the test, we aren't running it again
         * almost immediately (maybe the clock that gettimeofday uses is slow).
         * Try to jump ahead to the next scheduled repeat, or the start of the
         * next period if there are no repeats.
         */
        if ( run && llabs(diff) < SCHEDULE_CLOCK_FUDGE ) {
            if ( frequency > 0 ) {
                /* skip over the time we are early and find the next repeat */
                diff = llabs(diff) + frequency;
            } else {
                /* there is no repeat, find the start of next period */
                diff = llabs(diff) + (
                        (int64_t)get_period_max_value(period) * 1000000);
            }
        }

        /* convert usec to a timeval */
        next.tv_sec = llabs(diff) / 1000000;
        next.tv_usec = llabs(diff) % 1000000;

        /* save the absolute time this test was meant to be run */
        if ( abstime ) {
            timeradd(now, &next, abstime);
        }

        Log(LOG_DEBUG, "test triggered early, rescheduling for: %d.%d\n",
                (int)next.tv_sec, (int)next.tv_usec);

        return next;
    }

    if ( frequency == 0 ) {
	/*
         * If it's after the first and only event in the cycle, roll over.
         * This has to be a test that ran on time, otherwise we would have
         * had a negative difference at the earlier check.
         */
	next_repeat = 1;
    } else {
	/* if it's after the first event but repeated, find the next repeat */
	next_repeat = 0;
	diff %= frequency;
	diff = frequency - diff;

        /*
         * Make sure that if we just ran the test, we aren't running it again
         * almost immediately (maybe the clock that gettimeofday uses is slow).
         * Jump ahead to the next scheduled repeat.
         */
        if ( run && diff < SCHEDULE_CLOCK_FUDGE ) {
            diff += frequency;
        }

        next.tv_sec = diff / 1000000;
        next.tv_usec = diff % 1000000;
    }

    /* check that this next repeat is allowed at this time */
    period_end = period_start + get_period_max_value(period);
    if ( next_repeat || now->tv_sec + (diff/1000000) > period_end ||
            US_FROM_TV(*now) + diff > test_end ) {
        /* next time is after the end time for test, advance to next start */
        next.tv_sec = period_end - now->tv_sec;
        if ( now->tv_usec > 0 ) {
            next.tv_sec--;
            next.tv_usec = 1000000 - now->tv_usec;
        } else {
            next.tv_usec = 0;
        }
        ADD_TV_PARTS(next, next, start / 1000000, start % 1000000);
    }

    /* If somehow we get an invalid offset then throw all the calculations
     * out the window and just offset by the frequency. Better to have the
     * test scheduled roughly correct than to pass rubbish on to libevent.
     */
    if ( next.tv_sec < 0 || next.tv_usec < 0 || next.tv_usec >= 1000000 ) {
        Log(LOG_WARNING,
                "Failed to calculate sensible next time, using naive offset");
        if ( frequency == 0 ) {
            next.tv_sec = get_period_max_value(period);
            next.tv_usec = 0;
        } else {
            next.tv_sec = frequency / 1000000;
            next.tv_usec = 0;
        }
    }

    /* save the absolute time this test was meant to be run */
    if ( abstime ) {
        timeradd(now, &next, abstime);
    }

    Log(LOG_DEBUG, "next test run scheduled at: %d.%d\n", (int)next.tv_sec,
            (int)next.tv_usec);

    return next;
}

/*
 * To aid unit tests we have a wrapper around get_next_schedule_time that 
 * allows us to override the time taken from the event_base and set the 
 * time to anything we want. Also, have to make sure that we use this same
 * time result for everything - if we make multiple calls we could end up 
 * on either side of a period boundary or similar. libevent ensures this by
 * caching the internal time between events, so if
 * 'event_base_gettimeofday_cached' is called  multiple times within the same
 * event (or sequence of events) the time shall remain constant.
 */
struct timeval get_next_schedule_time(struct event_base *base,
        schedule_period_t period, uint64_t start, uint64_t end,
        uint64_t frequency, int run, struct timeval *abstime) {

    struct timeval now;
    if ( event_base_gettimeofday_cached(base, &now) != 0 ) {
        gettimeofday(&now, NULL);
    }

    return get_next_schedule_time_internal(&now, period, start, end, frequency,
            run, abstime);
}

/*
 * Compare two test schedule items to see if they are similar enough to
 * merge together to make one scheduled test with multiple destinations.
 */
static int compare_test_items(test_schedule_item_t *a, test_schedule_item_t *b){

    if ( a->test != b->test )
	return 0;

    if ( timercmp(&(a->interval), &(b->interval), !=) )
	return 0;

    if ( a->period != b->period )
	return 0;

    if ( a->start != b->start )
	return 0;

    if ( a->end != b->end )
	return 0;

    if ( a->params != NULL && b->params != NULL ) {
        int i;
	/* if both params are not null, make sure they are identical */
	for ( i=0; a->params[i] != NULL && b->params != NULL; i++ ) {
	    if ( strcmp(a->params[i], b->params[i]) != 0 )
		return 0;
	}

	/* if either isn't null by now then the params lists are different */
	if ( a->params[i] != NULL || b->params[i] != NULL ) {
	    return 0;
	}

    } else if ( a->params != NULL || b->params != NULL ) {
	/* if one of them is null they should both be null */
	return 0;
    }

    return 1;
}



/*
 * Callback that is used to find the first matching timer event, once a valid 
 * event is found the event is stored at the address pointed to by evdata
 */
int check_test_compare_callback(
        __attribute__((unused))const struct event_base *base,
        const struct event *ev, 
        void *evdata) {

    schedule_item_t *sched_item;
    test_schedule_item_t *sched_test;
    test_schedule_item_t *test;
    test_schedule_item_t **return_value = evdata;

    /*
     * test if event callback matches test callback
     * (libevent may have other events queued)
     */
    if ( event_get_callback(ev) != run_scheduled_test ) {
        return 0;
    }

    sched_item = event_get_callback_arg(ev);

    assert(sched_item->data.test);
    sched_test = sched_item->data.test;

    assert(*return_value);
    test = (*return_value);

    /* check if these tests are the same */
    if ( compare_test_items(sched_test, test) ) {

        /* check if there is room for more destinations */
        if ( test->test->max_targets == 0 ||
                (sched_test->dest_count + sched_test->resolve_count) <
                test->test->max_targets ) {

            /* valid matching sched_item was found */
            *return_value = sched_test;
            return 1;
        }
    }
    /* No match was found, move on to next item */
    return 0;
}



/*
 * Try to merge the given test with any currently scheduled tests that have
 * exactly the same schedule, parameters etc and also allow multiple
 * destinations. If the tests can be merged that helps to limit the number of
 * active timers and tests that need to be run.
 */
static int merge_scheduled_tests(
        struct event_base *base, 
        test_schedule_item_t *test) {

    test_schedule_item_t * sched_test = test;

    /* if entire events list was searched without returning then result is 0 */
    if ( event_base_foreach_event(base,
            check_test_compare_callback, &sched_test) ) {

        /* if status is non zero sched_test must contain a matching test */
        assert(sched_test != test);

        if ( test->dest_count > 0 ) {
            /* add a new pre-resolved address */
            sched_test->dests = realloc(sched_test->dests,
                    (sched_test->dest_count+1) *
                    sizeof(struct addrinfo *));
            sched_test->dests[sched_test->dest_count++] = test->dests[0];
        } else {
            /* add a new address we will need to resolve later */
            test->resolve->next = sched_test->resolve;
            sched_test->resolve = test->resolve;
            sched_test->resolve_count++;
        }
        return 1;
    }
    return 0;
}



/*
 * Get all of the target names from the "target" node in the test
 * configuration. They could be a single scalar, a sequence of scalars, or
 * indefinitely nested sequences eventually ending in scalars (this is what
 * you get when you start using yaml aliases).
 */
static char **parse_test_targets(yaml_document_t *document, yaml_node_t *node,
        char **targets, int *len) {

    if ( node->type == YAML_SCALAR_NODE ) {
        /* if we find a scalar then it is an actual target, add it */
        targets = realloc(targets, sizeof(char *) * (*len + 1));
        targets[(*len) - 1] = (char*)node->data.scalar.value;
        targets[*len] = NULL;
        (*len)++;

    } else if ( node->type == YAML_SEQUENCE_NODE ) {
        /* targets can included nested sequences arbitrarily deep, recurse */
        yaml_node_item_t *item;
        for ( item = node->data.sequence.items.start;
                item != node->data.sequence.items.top; item++ ) {
            targets = parse_test_targets(document,
                    yaml_document_get_node(document, *item), targets, len);
        }
    }

    return targets;
}



/*
 * Given a string array of targets from the schedule file, turn them all
 * into useful addresses from the nametable, or future addresses that need
 * to be resolved at test runtime.
 *
 * The schedule can determine how many addresses of what address families
 * are resolved:
 * www.foo.com	    -- resolve all addresses
 * www.foo.com!1    -- resolve a single address
 * www.foo.com!n    -- resolve up to n addresses
 * www.foo.com!v4   -- resolve all ipv4 addresses
 * www.foo.com!v6   -- resolve all ipv6 addresses
 * www.foo.com!n!v4 -- resolve up to n ipv4 addresses
 * www.foo.com!n!v6 -- resolve up to n ipv6 addresses
 */
char **populate_target_lists(test_schedule_item_t *test, char **targets) {

    char *addr_str, *count_str;
    int family;
    nametable_t *addresses;
    uint16_t count;
    uint16_t max_targets;

    max_targets = test->test->max_targets;
    test->dests = NULL;
    test->resolve = NULL;
    test->resolve_count = 0;
    test->dest_count = 0;

    /* for every address in the list, find it in nametable or set to resolve */
    for ( ; targets != NULL && *targets != NULL && (max_targets == 0 ||
            (test->dest_count + test->resolve_count) < max_targets);
            targets++ ) {
        addr_str = strtok(*targets, "!");
        family = AF_UNSPEC;
        count = 0;
        if ( (count_str=strtok(NULL, "!")) != NULL ) {
            do {
                if (strncmp(count_str, "*", 1) == 0 ) {
                    /* do nothing - backwards compatability with old format */
                } else if ( strncmp(count_str, "v4", 2) == 0 ) {
                    family = AF_INET;
                } else if ( strncmp(count_str, "v6", 2) == 0 ) {
                    family = AF_INET6;
                } else {
                    count = (uint16_t)atoi(count_str);
                }
            } while ( (count_str=strtok(NULL, "!")) != NULL );
        }

	/* check if the destination is in the nametable */
        if ( (addresses = name_to_address(addr_str)) != NULL ) {
            struct addrinfo *addr;

            /*
             * Add all the addresses in the addrinfo chain that match the
             * given family, up to the maximum count.
             */
            for ( addr=addresses->addr; addr != NULL; addr=addr->ai_next ) {
                if ( (max_targets > 0 &&
                        (test->dest_count + test->resolve_count) >= max_targets)
                    ||
                    (count > 0 &&
                        (test->dest_count + test->resolve_count) >= count) ) {
                    break;
                }

                if ( family == AF_UNSPEC || family == addr->ai_family ) {
                    test->dests = (struct addrinfo **)realloc(test->dests,
                            sizeof(struct addrinfo*) * (test->dest_count + 1));
                    test->dests[test->dest_count] = addr;
                    test->dest_count++;
                }
            }

	} else {
	    /* if it isn't then it will be resolved at test time */
            resolve_dest_t *dest;

	    Log(LOG_DEBUG, "Unknown destination '%s' will be resolved",
                    *targets);

            dest = (resolve_dest_t*)malloc(sizeof(resolve_dest_t));
	    dest->name = strdup(addr_str);
            dest->family = family;
	    dest->addr = NULL;
            dest->count = count;
	    dest->next = test->resolve;
            test->resolve = dest;
            test->resolve_count++;
	}
    }

    Log(LOG_DEBUG, "%d known targets, %d to resolve", test->dest_count,
            test->resolve_count);

    return targets;
}



/*
 * Create a new test schedule item and fill in the test configuration.
 * All the times are given by the user in seconds, but we'll use milliseconds
 * because it makes scheduling easier.
 */
static test_schedule_item_t *create_and_schedule_test(
        struct event_base *base, yaml_document_t *document,
        yaml_node_item_t index, amp_test_meta_t *meta) {

    test_schedule_item_t *test = NULL;
    schedule_item_t *sched;
    yaml_node_t *node, *key, *value;
    yaml_node_pair_t *pair;
    test_t *test_definition;
    int64_t start = 0, end = -1, frequency = -1;
    char *period_str = NULL, *testname = NULL, **params = NULL;
    schedule_period_t period;
    char **targets = NULL, **remaining = NULL;
    int target_len;
    struct timeval next;
    int params_present = 0;
    int lineno = 0;

    /* make sure the node exists and is of the right type */
    if ( (node = yaml_document_get_node(document, index)) == NULL ||
            node->type != YAML_MAPPING_NODE ) {
        return NULL;
    }

    /*
     * Save the line number for the start of the test definition, rather
     * than keeping line numbers for every attribute. The yaml mark seems
     * to point to the line before, so increment by one.
     */
    lineno = node->start_mark.line + 1;


    for ( pair = node->data.mapping.pairs.start;
            pair < node->data.mapping.pairs.top; pair++ ) {

        /* get the actual nodes rather than their indices */
        key = yaml_document_get_node(document, pair->key);
        value = yaml_document_get_node(document, pair->value);

        /* key has to be a scalar node, if it's not then this isn't for us */
        if ( key->type != YAML_SCALAR_NODE ) {
            goto end;
        }

        /* read the appropriate value based on the key, could be in any order */
        if ( strcmp((char*)key->data.scalar.value, "test") == 0 ) {
            assert(value->type == YAML_SCALAR_NODE);
            testname = (char*)value->data.scalar.value;
        } else if ( strcmp((char*)key->data.scalar.value, "frequency") == 0 ) {
            assert(value->type == YAML_SCALAR_NODE);
            frequency = atoi((char*)value->data.scalar.value);
            frequency *= 1000000;
        } else if ( strcmp((char*)key->data.scalar.value, "start") == 0 ) {
            assert(value->type == YAML_SCALAR_NODE);
            start = atoi((char*)value->data.scalar.value);
            start *= 1000000;
        } else if ( strcmp((char*)key->data.scalar.value, "end") == 0 ) {
            assert(value->type == YAML_SCALAR_NODE);
            end = atoi((char*)value->data.scalar.value);
            end *= 1000000;
        } else if ( strcmp((char*)key->data.scalar.value, "period") == 0 ) {
            assert(value->type == YAML_SCALAR_NODE);
            period_str = (char*)value->data.scalar.value;
        } else if ( strcmp((char*)key->data.scalar.value, "args") == 0 ) {
            assert(value->type == YAML_SCALAR_NODE);
            params = parse_param_string((char*)value->data.scalar.value);
            params_present = 1;
        } else if ( strcmp((char*)key->data.scalar.value, "target") == 0 ) {
            /* it's possible "target" could be defined multiple times */
            if ( targets == NULL ) {
                targets = (char**)malloc(sizeof(char*));
                targets[0] = NULL;
                target_len = 1;
            }
            targets = parse_test_targets(document, value, targets, &target_len);
        }
    }

    /* confirm the test name is valid */
    if ( testname == NULL ||
            (test_definition = get_test_by_name(testname)) == NULL ) {
        Log(LOG_WARNING, "Unknown test '%s' (from line %d)", testname, lineno);
        goto end;
    }

    /* need to figure out the period before we can do much else */
    if ( period_str == NULL ) {
        period = SCHEDULE_PERIOD_DAILY;
    } else if ( (period =
                get_period_label(period_str)) == SCHEDULE_PERIOD_INVALID ) {
        Log(LOG_WARNING, "Invalid period: '%s' (from line %d)",
                period_str, lineno);
        goto end;
    }

    /* now that the period is determined, we can validate the other values */
    if ( check_time_range(start, period) < 0 ) {
        Log(LOG_WARNING,
                "Invalid start value %" PRId64 " for period %s (from line %d)",
                start, period_str, lineno);
        goto end;
    }

    /* default to the end of the period if not set */
    if ( end < 0 ) {
        end = ((int64_t)get_period_max_value(period)) * 1000000;
    } else if ( check_time_range(end, period) < 0 ) {
        Log(LOG_WARNING,
                "Invalid end value %" PRId64 " for period %s (from line %d)",
                end, period_str, lineno);
        goto end;
    }

    /* default to a vaguely sensible frequency if not set */
    if ( frequency < 0 ) {
        frequency = get_period_default_frequency(period) * 1000000;
    } else if ( check_time_range(frequency, period) < 0 ) {
        Log(LOG_WARNING,
                "Invalid frequency value %d for period %s (from line %d)",
                frequency, period_str, lineno);
        goto end;
    }

    if ( params_present && params == NULL ) {
        Log(LOG_WARNING, "Incorrectly formed argument string (from line %d)",
                lineno);
        goto end;
    }

    Log(LOG_DEBUG, "start:%" PRId64 " end:%" PRId64 " freq:%" PRId64
            " period:%" PRId64, start, end, frequency, period);

    remaining = targets;

    do {
        Log(LOG_DEBUG, "Creating test schedule instance for %s test", testname);
        /* if everything looks good, finally construct the test object */
        test = (test_schedule_item_t *)malloc(sizeof(test_schedule_item_t));
        test->interval.tv_sec = frequency / 1000000;
        test->interval.tv_usec = frequency % 1000000;
        test->period = period;
        test->start = start;
        test->end = end;
        test->test = test_definition;
        test->params = params;
        test->meta = meta;
        /*
         * Convert the list of targets into actual dests and ones to resolve.
         * We update the list to only point at the remainder (if there are
         * any left due to destination count limitations).
         */
        remaining = populate_target_lists(test, remaining);

        /* don't bother scheduling any tests without valid destinations */
        if ( (test->dest_count + test->resolve_count) <
                test_definition->min_targets ) {
            Log(LOG_WARNING, "%s test scheduled with too few targets, ignoring",
                    testname);
            free_test_schedule_item(test);
            break;
        }

        /*
         * See if we can merge this test with an existing one. Obviously if
         * there are still outstanding targets then the test is maxed out and
         * there is no room for more destinations.
         */
        if ( remaining != NULL && *remaining == NULL &&
                test_definition->max_targets != 1 ) {
            /* check if this test at this time already exists */
            if ( merge_scheduled_tests(base, test) ) {
                /* remove pointer to names, merged test owns it */
                test->resolve = NULL;
                /* free this test, it has now merged */
                free_test_schedule_item(test);
                break;
            }
        }

        sched = (schedule_item_t *)malloc(sizeof(schedule_item_t));
        sched->type = EVENT_RUN_TEST;
        sched->data.test = test;
        sched->base = base;

        /* create the timer event for this test */
        next = get_next_schedule_time(base, test->period, test->start,
                test->end, US_FROM_TV(test->interval), 0, &test->abstime);

        sched->event = event_new(sched->base, -1,
            0, run_scheduled_test, sched);

        if ( event_add(sched->event, &next) != 0 ) {
            Log(LOG_ALERT, "Failed to schedule %s test", testname);
        }

    } while ( remaining != NULL && *remaining != NULL );

end:
    if ( targets ) {
        free(targets);
    }

    return test;
}



/*
 * Read in the schedule file and create events for each test.
 */
static void read_schedule_file(struct event_base *base, char *filename,
        amp_test_meta_t *meta) {

    FILE *in;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root;
    yaml_node_pair_t *pair;

    assert(base);
    assert(filename);

    Log(LOG_INFO, "Loading schedule from %s", filename);

    if ( (in = fopen(filename, "r")) == NULL ) {
	Log(LOG_WARNING, "Failed to open schedule file %s: %s\n",
                filename, strerror(errno));
        return;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    /* make sure that the schedule file is valid yaml */
    if ( !yaml_parser_load(&parser, &document) ) {
        Log(LOG_WARNING, "Malformed schedule file %s, skipping", filename);
        goto parser_load_error;
    }

    /* and make sure that there is actually something in it */
    if ( (root = yaml_document_get_root_node(&document)) == NULL ) {
        Log(LOG_WARNING, "Empty schedule file %s, skipping", filename);
        goto parser_format_error;
    }

    /*
     * The top level should be a mapping node with the key "tests", but
     * there may also be other keys. Look through the map till we find the
     * one we want.
     */
     if ( root->type != YAML_MAPPING_NODE ) {
        Log(LOG_WARNING, "Malformed schedule file %s, skipping", filename);
        goto parser_format_error;
     }

     for ( pair = root->data.mapping.pairs.start;
             pair < root->data.mapping.pairs.top; pair++ ) {
        yaml_node_t *key = yaml_document_get_node(&document, pair->key);
        yaml_node_t *value = yaml_document_get_node(&document, pair->value);

        /* find the "tests" key and make sure it has the correct types */
        if ( key->type == YAML_SCALAR_NODE &&
                value->type == YAML_SEQUENCE_NODE &&
                strcmp((char*)key->data.scalar.value, "tests") == 0 ) {
            /* for each item in the tests array, create the test */
            yaml_node_item_t *item;
            for ( item = value->data.sequence.items.start;
                    item != value->data.sequence.items.top; item++ ) {
                create_and_schedule_test(base, &document, *item, meta);
            }
        }
     }

parser_format_error:
     yaml_document_delete(&document);
     yaml_parser_delete(&parser);

parser_load_error:
     fclose(in);
}



/*
 * Read all the test schedule files in the given directory and add their
 * contents to the global test schedule.
 */
void read_schedule_dir(struct event_base *base, char *directory,
        amp_test_meta_t *meta) {

    glob_t glob_buf;
    unsigned int i;
    char full_loc[MAX_PATH_LENGTH];

    assert(base);
    assert(directory);
    assert(strlen(directory) < MAX_PATH_LENGTH - 8);
    assert(meta);

    /*
     * Using glob makes it easy to treat every non-dotfile in the schedule
     * directory as a schedule file. Also makes it easy if we want to restrict
     * the list of files further with a prefix/suffix.
     */
    strcpy(full_loc, directory);
    strcat(full_loc, "/*.sched");
    glob(full_loc, 0, NULL, &glob_buf);

    Log(LOG_INFO, "Loading schedule from %s (found %zd candidates)",
            directory, glob_buf.gl_pathc);

    for ( i = 0; i < glob_buf.gl_pathc; i++ ) {
        read_schedule_file(base, glob_buf.gl_pathv[i], meta);
    }

    globfree(&glob_buf);
    return;
}



/*
 * Try to fetch a schedule file from a remote server if there is a fresher one
 * available, replacing any existing one that has been previously fetched.
 * Returns -1 on error, 0 if no update was needed, 1 if the file was
 * successfully fetched and updated.
 *
 * TODO keep history of downloaded schedules? Previous 1 or 2?
 * TODO connection timeout should be short, to not delay startup?
 */
static int update_remote_schedule(fetch_schedule_item_t *fetch, int clobber) {
    CURL *curl;

    Log(LOG_DEBUG, "Fetching remote schedule file from %s (clobber=%d)",
            fetch->schedule_url, clobber);

    curl = curl_easy_init();

    if ( curl ) {
        CURLcode res;
        int stat_result;
        struct stat statbuf;
        long code;
        long filetime;
        long cond_unmet;
        double length;
        FILE *tmpfile;
        char errorbuf[CURL_ERROR_SIZE];
        char tmp_sched_file[MAX_PATH_LENGTH];
        char sched_file[MAX_PATH_LENGTH];

        /*
         * TODO Can we move towards asprintf stuff rather than fixed buffers?
         * This sort of thing is icky and problematic.
         */
        snprintf(tmp_sched_file, MAX_PATH_LENGTH-1, "%s/%s",fetch->schedule_dir,
                TMP_REMOTE_SCHEDULE_FILE);
        tmp_sched_file[MAX_PATH_LENGTH-1] = '\0';

        snprintf(sched_file, MAX_PATH_LENGTH-1, "%s/%s", fetch->schedule_dir,
                REMOTE_SCHEDULE_FILE);
        sched_file[MAX_PATH_LENGTH-1] = '\0';

        /* make sure the schedule directory exists */
        stat_result = stat(fetch->schedule_dir, &statbuf);

        if ( stat_result < 0 && errno == ENOENT) {
            Log(LOG_DEBUG, "Schedule dir doesn't exist, creating %s",
                    fetch->schedule_dir);
            /* doesn't exist, try to create it */
            if ( mkdir(fetch->schedule_dir, 0755) < 0 ) {
                Log(LOG_WARNING, "Failed to create schedule directory %s: %s",
                        fetch->schedule_dir, strerror(errno));
                curl_easy_cleanup(curl);
                return -1;
            }
        } else if ( stat_result < 0 ) {
            /* error calling stat, report it and return */
            Log(LOG_WARNING, "Failed to stat schedule directory %s: %s",
                    fetch->schedule_dir, strerror(errno));
            curl_easy_cleanup(curl);
            return -1;
        }

        /* Open the temporary file we read the remote schedule into */
        if ( (tmpfile = fopen(tmp_sched_file, "w")) == NULL ) {
            Log(LOG_WARNING, "Failed to open temporary schedule %s: %s",
                    tmp_sched_file, strerror(errno));
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, fetch->schedule_url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
        curl_easy_setopt(curl, CURLOPT_FILETIME, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, tmpfile);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        /* get slightly more detailed error messages, useful with ssl */
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);

        /* use ssl if required (a good idea to at least validate the server) */
        if ( strncasecmp(fetch->schedule_url, "https", strlen("https")) == 0 ) {
            /*
             * Set the CA cert that we validate the server against,
             * otherwise use the default cacert bundle.
             */
            if ( fetch->cacert != NULL ) {
                Log(LOG_DEBUG, "CACERT=%s", fetch->cacert);
                curl_easy_setopt(curl, CURLOPT_CAINFO, fetch->cacert);
            }

            /* set the client cert and key that we present the server */
            if ( fetch->cert != NULL && fetch->key != NULL ) {
                Log(LOG_DEBUG, "KEY=%s", fetch->key);
                Log(LOG_DEBUG, "CERT=%s", fetch->cert);

                curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
                curl_easy_setopt(curl, CURLOPT_SSLCERT, fetch->cert);
                curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
                curl_easy_setopt(curl, CURLOPT_SSLKEY, fetch->key);
            }

            /* Try to verify the server certificate */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
            /* Try to verify the server hostname/commonname */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
        }

        /*
         * Check if remote schedule file exists locally, and when it was last
         * modified. If it doesn't exist we fetch it, if it does exist then we
         * fetch it conditional on there being a newer version.
         */
        stat_result = stat(sched_file, &statbuf);

        if ( stat_result < 0 && errno != ENOENT) {
            /* don't fetch the file, something is wrong with the path */
            Log(LOG_WARNING, "Failed to stat schedule file %s: %s",
                    sched_file, strerror(errno));
            fclose(tmpfile);
            curl_easy_cleanup(curl);
            return -1;

        } else if ( clobber == 0 && stat_result == 0 ) {
            /* we have a file already, only fetch if there is a newer one */
            curl_easy_setopt(curl, CURLOPT_TIMECONDITION,
                    CURL_TIMECOND_IFMODSINCE);
            curl_easy_setopt(curl, CURLOPT_TIMEVALUE, statbuf.st_mtime);
            Log(LOG_DEBUG, "Local schedule Last-Modified:%d", statbuf.st_mtime);
        }

        /* perform the GET */
        res = curl_easy_perform(curl);

        /* close our temporary file, it is either empty or full of new data */
        fclose(tmpfile);

        /* don't do anything if the file wasn't fetched ok */
        if ( res != CURLE_OK ) {
            Log(LOG_WARNING, "Failed to fetch remote schedule: %s",
                    curl_easy_strerror(res));
            Log(LOG_WARNING, "%s", errorbuf);
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &length);
#if LIBCURL_VERSION_NUM >= 0x071309
        if ( clobber == 0 ) {
            curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &cond_unmet);
        } else {
            cond_unmet = 0;
        }
#else
        cond_unmet = 0;
#endif
        curl_easy_cleanup(curl);

        Log(LOG_DEBUG, "HTTP %ld Last-Modified:%d Length:%.0f",
                code, filetime, length);

        /* if a new file was fetched then move it into position */
        if ( code == 200 && cond_unmet == 0 && length > 0 ) {
            Log(LOG_INFO, "New schedule file fetched from %s",
                    fetch->schedule_url);
            if ( rename(tmp_sched_file, sched_file) < 0 ) {
                Log(LOG_WARNING,
                        "Error moving fetched schedule file %s to %s: %s",
                        tmp_sched_file, sched_file, strerror(errno));
                return -1;
            }
            return 1;
        }

        Log(LOG_DEBUG, "No new schedule file available");
        return 0;
    }

    Log(LOG_WARNING,
            "Failed to initialise curl, skipping fetch of remote schedule");
    return -1;
}



/*
 * Fork a process to check for a more up to date schedule file from a remote
 * server.
 */
static void fork_and_fetch(fetch_schedule_item_t *fetch, int clobber) {
    pid_t pid;

    /* fork off a process to do the actual check */
    if ( (pid = fork()) < 0 ) {
        Log(LOG_WARNING, "Failed to fork for fetching remote schedule: %s",
                strerror(errno));
        return;
    } else if ( pid == 0 ) {
        timer_t watchdog;

        /* unblock signals and remove handlers that the parent process added */
        if ( unblock_signals() < 0 ) {
            Log(LOG_WARNING, "Failed to unblock signals, aborting");
            exit(EXIT_FAILURE);
        }

        /* add a watchdog to make sure this doesn't sit around forever */
        if ( start_watchdog(SCHEDULE_FETCH_TIMEOUT, SIGKILL, &watchdog) < 0 ) {
            Log(LOG_WARNING, "Not fetching remote schedule file");
            exit(EXIT_FAILURE);
        }

        set_proc_name("schedule fetch");

        if ( update_remote_schedule(fetch, clobber) > 0 ) {
            /* send SIGUSR1 to parent to reload schedule */
            Log(LOG_DEBUG, "Sending SIGUSR1 to parent to reload schedule");
            kill(getppid(), SIGUSR1);
        }

        stop_watchdog(watchdog);
        free_duped_environ();

        exit(EXIT_SUCCESS);
    }
}



/*
 * Callback for the manually fired user signal to trigger a schedule fetch.
 */
void signal_fetch_callback(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void * evdata) {

    Log(LOG_DEBUG, "Refetching schedule due to signal");
    fork_and_fetch((fetch_schedule_item_t *)evdata, 1);
}



/*
 * Callback for the timer that triggers a schedule fetch.
 */
static void timer_fetch_callback(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void *evdata) {

    schedule_item_t *item;
    fetch_schedule_item_t *fetch;

    Log(LOG_DEBUG, "Timer fired for remote schedule checking");

    item = (schedule_item_t *)evdata;
    assert(item->type == EVENT_FETCH_SCHEDULE);

    fetch = (fetch_schedule_item_t *)item->data.fetch;

    fork_and_fetch(fetch, 0);

    struct timeval timeout = (struct timeval) {
            fetch->frequency,
            fetch->frequency};

    /* reschedule checking for schedule updates */
    if ( event_add(item->event, &timeout) != 0 ) {
        Log(LOG_ALERT, "Failed to reschedule remote update check");
    }
}



/*
 * Try to fetch the remote schedule right now, and create the recurring event
 * that will check for new schedules in the future.
 */
int enable_remote_schedule_fetch(struct event_base *base,
        fetch_schedule_item_t *fetch) {

    schedule_item_t *item;

    assert(base);

    if ( fetch == NULL ) {
        Log(LOG_DEBUG, "Remote schedule fetching disabled");
        return 0;
    }

    if ( fetch->schedule_url == NULL ) {
        Log(LOG_WARNING, "Remote schedule fetching missing URL, skipping!");
        return 0;
    }

    /* do a fetch now, while blocking the main process */
    update_remote_schedule(fetch, 1);

    item = (schedule_item_t *)malloc(sizeof(schedule_item_t));
    item->type = EVENT_FETCH_SCHEDULE;
    item->base = base;
    item->data.fetch = fetch;
    item->event = event_new(base, -1, 0, timer_fetch_callback, item);

    struct timeval timeout = (struct timeval) {
            fetch->frequency,
            fetch->frequency};

    /* create the timer event for fetching schedules */
    if ( event_add(item->event, &timeout) != 0 ) {
        Log(LOG_ALERT, "Failed to schedule remote update check");
        return -1;
    }

    return 0;
}



#if UNIT_TEST
time_t amp_test_get_period_max_value(char repeat) {
    return get_period_max_value(repeat);
}
int64_t amp_test_check_time_range(int64_t value, schedule_period_t period) {
    return check_time_range(value, period);
}
time_t amp_test_get_period_start(char repeat, time_t *now) {
    return get_period_start(repeat, now);
}
struct timeval amp_test_get_next_schedule_time(struct timeval *time_pass,
        schedule_period_t period, uint64_t start, uint64_t end,
        uint64_t frequency, int run, struct timeval *abstime) {
    return get_next_schedule_time_internal(time_pass, period, start, end, frequency,
            run, abstime);
}
#endif
