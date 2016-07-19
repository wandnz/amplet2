#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include <libwandevent.h>

#include "config.h"
#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "nametable.h"
#include "debug.h"
#include "modules.h"
#include "testlib.h"



/*
 * Dump a debug information line about a scheduled test.
 */
static void dump_event_run_test(test_schedule_item_t *item, FILE *out) {

    assert(item);

    fprintf(out, "EVENT_RUN_TEST ");
    fprintf(out, "%s %d.%.6d", amp_tests[item->test_id]->name,
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



/*
 * Dump the current schedule for debug purposes
 */
void dump_schedule(wand_event_handler_t *ev_hdl, FILE *out) {
    struct wand_timer_t *timer;
    schedule_item_t *item;
    struct timeval mono, wall, offset;

    assert(out);

    mono = wand_get_monotonictime(ev_hdl);
    wall = wand_get_walltime(ev_hdl);

    fprintf(out, "===== SCHEDULE at %d.%d =====\n", (int)wall.tv_sec,
            (int)wall.tv_usec);

    for ( timer=ev_hdl->timers; timer != NULL; timer=timer->next ) {
        timersub(&timer->expire, &mono, &offset);
	fprintf(out, "%d.%.6d ", (int)offset.tv_sec, (int)offset.tv_usec);
	if ( timer->data == NULL ) {
	    fprintf(out, "NULL\n");
	    continue;
	}

	/* TODO add file refresh timers to this list */
	item = (schedule_item_t *)timer->data;
	switch ( item->type ) {
	    case EVENT_RUN_TEST:
                dump_event_run_test(item->data.test, out);
                break;
            case EVENT_FETCH_SCHEDULE:
                dump_event_fetch_schedule(item->data.fetch, out);
                break;
	    default: fprintf(out, "UNKNOWN\n"); continue;
	};
    }
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
 *
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
 * Walk the list of timers and remove all of them, or just those that are
 * scheduled tests. Refreshing the test schedule will still leave schedule
 * fetches in the list.
 */
void clear_test_schedule(wand_event_handler_t *ev_hdl, int all) {
    struct wand_timer_t *timer = ev_hdl->timers;
    struct wand_timer_t *tmp;
    schedule_item_t *item;

    while ( timer != NULL ) {
	tmp = timer;
	timer = timer->next;
	/* only remove future scheduled tests */
	if ( tmp->data != NULL ) {
	    item = (schedule_item_t *)tmp->data;

            /* We can clear just the test schedule, or all timer events */
            if ( !all && item->type != EVENT_RUN_TEST ) {
                continue;
            }

            wand_del_timer(ev_hdl, tmp);

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
	}
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
 *
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
 * TODO do we need to check the parameters here, given they are going to be
 * used as part of the parameter array given to execv?
 */
char **parse_param_string(char *param_string) {
    int i;
    char *tmp, *arg;
    char **result;

    if ( param_string == NULL ) {
        return NULL;
    }

    /* TODO we can realloc this as we go */
    result = (char**)malloc(sizeof(char*) * MAX_TEST_ARGS);

    /* splitting on space, grab each part of the parameter string into array */
    for ( i = 0, tmp = param_string; ; i++, tmp = NULL ) {
	arg = strtok(tmp, " \n");
	if ( arg == NULL )
	    break;
	result[i] = strdup(arg);
    }

    /* param list should be null terminated */
    result[i] = NULL;
    return result;
}



/*
 * Calculate the next time that a test is due to be run and return a timeval
 * with an offset appropriate for use with libwandevent scheduling. We have to
 * use an offset because libwandevent schedules relative to a monotonic clock,
 * not the system clock.
 *
 * TODO what sizes do we want to use for time values?
 */
struct timeval get_next_schedule_time(wand_event_handler_t *ev_hdl,
	schedule_period_t period, uint64_t start, uint64_t end,
        uint64_t frequency, int run, struct timeval *abstime) {

    time_t period_start, period_end;
    struct timeval now, next = {0,0};
    int64_t diff, test_end;
    int next_repeat;

    /*
     * wand_get_walltime essentially just calls gettimeofday(), but it lets
     * us write unit tests easier because we can cheat and set the time to
     * anything we want. Also, have to make sure that we use this same time
     * result for everything - if we make multiple calls we could end up on
     * either side of a period boundary or similar.
     */
    now = wand_get_walltime(ev_hdl);

    period_start = get_period_start(period, &now.tv_sec);
    test_end = (period_start * INT64_C(1000000)) + end;

    /* get difference in us between the first event of this period and now */
    diff = now.tv_sec - period_start;
    diff *= 1000000;
    diff += now.tv_usec;
    diff -= start;

    /* if the difference is negative, we are before the first scheduled run */
    if ( diff < 0 ) {
        /*
         * Make sure that if we just ran the test, we aren't running it again
         * almost immediately (maybe the clock that gettimeofday uses is slow).
         * Try to jump ahead to the next scheduled repeat, or the start of the
         * next period if there are no repeats.
         */
        if ( run && abs(diff) < SCHEDULE_CLOCK_FUDGE ) {
            if ( frequency > 0 ) {
                /* skip over the time we are early and find the next repeat */
                diff = abs(diff) + frequency;
            } else {
                /* there is no repeat, find the start of next period */
                diff = abs(diff) + get_period_max_value(period);
            }
        }

        /* convert usec to a timeval */
        next.tv_sec = abs(diff) / 1000000;
        next.tv_usec = abs(diff) % 1000000;

        /* save the absolute time this test was meant to be run */
        if ( abstime ) {
            timeradd(&now, &next, abstime);
        }

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
    if ( next_repeat || now.tv_sec + (diff/1000000) > period_end ||
	    US_FROM_TV(now) + diff > test_end ) {
	/* next time is after the end time for test, advance to next start */
	next.tv_sec = period_end - now.tv_sec;
        if ( now.tv_usec > 0 ) {
            next.tv_sec--;
            next.tv_usec = 1000000 - now.tv_usec;
        } else {
            next.tv_usec = 0;
        }
	ADD_TV_PARTS(next, next, start / 1000000, start % 1000000);
    }

    /* If somehow we get an invalid offset then throw all the calculations
     * out the window and just offset by the frequency. Better to have the
     * test scheduled roughly correct than to pass rubbish on to libwandevent.
     */
    if ( next.tv_sec < 0 || next.tv_usec < 0 || next.tv_usec >= 1000000 ) {
        Log(LOG_WARNING,
                "Failed to calculate sensible next time, using naive offset");
        if ( frequency == 0 ) {
            next.tv_sec = get_period_max_value(period) / 1000000;
            next.tv_usec = 0;
        } else {
            next.tv_sec = frequency / 1000000;
            next.tv_usec = 0;
        }
    }

    /* save the absolute time this test was meant to be run */
    if ( abstime ) {
        timeradd(&now, &next, abstime);
    }

    Log(LOG_DEBUG, "next test run scheduled at: %d.%d\n", (int)next.tv_sec,
	    (int)next.tv_usec);

    return next;
}



/*
 * Compare two test schedule items to see if they are similar enough to
 * merge together to make one scheduled test with multiple destinations.
 */
static int compare_test_items(test_schedule_item_t *a, test_schedule_item_t *b){

    if ( a->test_id != b->test_id )
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
 * Try to merge the given test with any currently scheduled tests that have
 * exactly the same schedule, parameters etc and also allow multiple
 * destinations. If the tests can be merged that helps to limit the number of
 * active timers and tests that need to be run.
 */
static int merge_scheduled_tests(struct wand_event_handler_t *ev_hdl,
	test_schedule_item_t *item) {

    struct wand_timer_t *timer;
    schedule_item_t *sched_item;
    test_schedule_item_t *sched_test;
    struct timeval when, expire;

    /* find the time that the timer for this test should expire */
    when = get_next_schedule_time(ev_hdl, item->period, item->start, item->end,
	    US_FROM_TV(item->interval), 0, NULL);
    expire = wand_calc_expire(ev_hdl, when.tv_sec, when.tv_usec);

    /* search all existing scheduled test timers for a test that matches */
    for ( timer=ev_hdl->timers; timer != NULL; timer=timer->next ) {

	/* give up if we get past the time the test should occur */
	if ( timercmp(&(timer->expire), &expire, >) ) {
	    return 0;
	}

	/* all our timers should have data, but maybe not... */
	if ( timer->data == NULL ) {
	    continue;
	}

	sched_item = (schedule_item_t *)timer->data;

	/* ignore non-test timers, we can't match them */
	if ( sched_item->type != EVENT_RUN_TEST ) {
	    continue;
	}

	assert(sched_item->data.test);
	sched_test = sched_item->data.test;

	/* check if these tests are the same */
	if ( compare_test_items(sched_test, item) ) {

	    /* check if there is room for more destinations */
	    if ( amp_tests[item->test_id]->max_targets == 0 ||
		    (sched_test->dest_count + sched_test->resolve_count) <
		    amp_tests[item->test_id]->max_targets ) {

		/*fprintf(stderr, "merging tests\n");*/

		/*
	 	 * resize the dests pointers to make room for the new dest
		 * TODO be smarter about resizing
		 */
		if ( item->dest_count > 0 ) {
		    /* add a new pre-resolved address */
		    sched_test->dests = realloc(sched_test->dests,
			    (sched_test->dest_count+1) *
			    sizeof(struct addrinfo *));
		    sched_test->dests[sched_test->dest_count++] =
			item->dests[0];
		} else {
		    /* add a new address we will need to resolve later */
		    item->resolve->next = sched_test->resolve;
		    sched_test->resolve = item->resolve;
		    sched_test->resolve_count++;
		}

		return 1;
	    }
	}
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
 * www.foo.com:1    -- resolve a single address
 * www.foo.com:n    -- resolve up to n addresses
 * www.foo.com:v4   -- resolve all ipv4 addresses
 * www.foo.com:v6   -- resolve all ipv6 addresses
 * www.foo.com:n:v4 -- resolve up to n ipv4 addresses
 * www.foo.com:n:v6 -- resolve up to n ipv6 addresses
 */
char **populate_target_lists(test_schedule_item_t *test, char **targets) {

    char *addr_str, *count_str;
    int family;
    nametable_t *addresses;
    int count;
    uint16_t max_targets;

    max_targets = amp_tests[test->test_id]->max_targets;
    test->dests = NULL;
    test->resolve = NULL;
    test->resolve_count = 0;
    test->dest_count = 0;

    /* for every address in the list, find it in nametable or set to resolve */
    for ( ; targets != NULL && *targets != NULL && (max_targets == 0 ||
            (test->dest_count + test->resolve_count) < max_targets);
            targets++ ) {
        addr_str = strtok(*targets, ":");
        family = AF_UNSPEC;
        count = 0;
        if ( (count_str=strtok(NULL, ":")) != NULL ) {
            do {
                if (strncmp(count_str, "*", 1) == 0 ) {
                    /* do nothing - backwards compatability with old format */
                } else if ( strncmp(count_str, "v4", 2) == 0 ) {
                    family = AF_INET;
                } else if ( strncmp(count_str, "v6", 2) == 0 ) {
                    family = AF_INET6;
                } else {
                    count = atoi(count_str);
                }
            } while ( (count_str=strtok(NULL, ":")) != NULL );
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
        wand_event_handler_t *ev_hdl, yaml_document_t *document,
        yaml_node_item_t index, amp_test_meta_t *meta) {

    test_schedule_item_t *test = NULL;
    schedule_item_t *sched;
    yaml_node_t *node, *key, *value;
    yaml_node_pair_t *pair;
    test_type_t test_id;
    int64_t start = 0, end = -1, frequency = -1;
    char *period_str = NULL, *testname = NULL, **params = NULL;
    schedule_period_t period;
    char **targets = NULL, **remaining = NULL;
    int target_len;
    struct timeval next;

    /* make sure the node exists and is of the right type */
    if ( (node = yaml_document_get_node(document, index)) == NULL ||
            node->type != YAML_MAPPING_NODE ) {
        return NULL;
    }

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
            (test_id = get_test_id(testname)) == AMP_TEST_INVALID ) {
        Log(LOG_WARNING, "Unknown test '%s'", testname);
        goto end;
    }

    /* need to figure out the period before we can do much else */
    if ( period_str == NULL ) {
        period = SCHEDULE_PERIOD_DAILY;
    } else if ( (period =
                get_period_label(period_str)) == SCHEDULE_PERIOD_INVALID ) {
        Log(LOG_WARNING, "Invalid period: '%s'", period_str);
        goto end;
    }

    /* now that the period is determined, we can validate the other values */
    if ( check_time_range(start, period) < 0 ) {
        Log(LOG_WARNING, "Invalid start value %d for period %s\n",
                start, period_str);
        goto end;
    }

    /* default to the end of the period if not set */
    if ( end < 0 ) {
        end = ((int64_t)get_period_max_value(period)) * 1000000;
    } else if ( check_time_range(end, period) < 0 ) {
        Log(LOG_WARNING, "Invalid end value %d for period %s\n",
                end, period_str);
        goto end;
    }

    /* default to a vaguely sensible frequency if not set */
    if ( frequency < 0 ) {
        frequency = get_period_default_frequency(period);
    } else if ( check_time_range(frequency, period) < 0 ) {
        Log(LOG_WARNING, "Invalid frequency value %d for period %s\n",
                frequency, period_str);
        goto end;
    }

    Log(LOG_DEBUG, "start:%d end:%d freq:%d period:%d", start, end, frequency,
            period);

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
        test->test_id = test_id;
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
                amp_tests[test->test_id]->min_targets ) {
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
                amp_tests[test->test_id]->max_targets != 1 ) {
            /* check if this test at this time already exists */
            if ( merge_scheduled_tests(ev_hdl, test) ) {
                /* remove pointer to names, merged test owns it */
                test->resolve = NULL;
                /* free this test, it has now merged */
                free_test_schedule_item(test);
                break;
            }
        }

        sched = (schedule_item_t *)malloc(sizeof(schedule_item_t));
        sched->type = EVENT_RUN_TEST;
        sched->ev_hdl = ev_hdl;
        sched->data.test = test;

        /* create the timer event for this test */
        next = get_next_schedule_time(ev_hdl, test->period, test->start,
                test->end, US_FROM_TV(test->interval), 0, &test->abstime);

        if ( wand_add_timer(ev_hdl, next.tv_sec, next.tv_usec, sched,
                run_scheduled_test) == NULL ) {
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
static void read_schedule_file(wand_event_handler_t *ev_hdl, char *filename,
        amp_test_meta_t *meta) {

    FILE *in;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root;
    yaml_node_pair_t *pair;

    assert(ev_hdl);
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
                create_and_schedule_test(ev_hdl, &document, *item, meta);
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
 *
 */
void read_schedule_dir(wand_event_handler_t *ev_hdl, char *directory,
        amp_test_meta_t *meta) {

    glob_t glob_buf;
    unsigned int i;
    char full_loc[MAX_PATH_LENGTH];

    assert(ev_hdl);
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
	read_schedule_file(ev_hdl, glob_buf.gl_pathv[i], meta);
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
 * TODO put error strings in based on errno for useful messages
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
            Log(LOG_WARNING, "Failed to stat schedule file %s", sched_file);
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
                Log(LOG_WARNING, "Error moving fetched schedule file %s to %s",
                        tmp_sched_file, sched_file);
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
 *
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
            exit(1);
        }

        /* add a watchdog to make sure this doesn't sit around forever */
        if ( start_watchdog(SCHEDULE_FETCH_TIMEOUT, SIGKILL, &watchdog) < 0 ) {
            Log(LOG_WARNING, "Not fetching remote schedule file");
            exit(-1);
        }

        set_proc_name("schedule fetch");

        if ( update_remote_schedule(fetch, clobber) > 0 ) {
            /* send SIGUSR1 to parent to reload schedule */
            Log(LOG_DEBUG, "Sending SIGUSR1 to parent to reload schedule");
            kill(getppid(), SIGUSR1);
        }

        stop_watchdog(watchdog);
        exit(0);
    }
}



/*
 *
 */
void signal_fetch_callback(
        __attribute__((unused))wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum, void *data) {

    Log(LOG_DEBUG, "Refetching schedule due to signal");
    fork_and_fetch((fetch_schedule_item_t *)data, 1);
}



/*
 *
 */
static void timer_fetch_callback(wand_event_handler_t *ev_hdl, void *data) {
    schedule_item_t *item;
    fetch_schedule_item_t *fetch;

    Log(LOG_DEBUG, "Timer fired for remote schedule checking");

    item = (schedule_item_t *)data;
    assert(item->type == EVENT_FETCH_SCHEDULE);

    fetch = (fetch_schedule_item_t *)item->data.fetch;

    fork_and_fetch(fetch, 0);

    /* reschedule checking for schedule updates */
    if ( wand_add_timer(ev_hdl, fetch->frequency, 0, data,
                timer_fetch_callback) == NULL ) {
        Log(LOG_ALERT, "Failed to reschedule remote update check");
    }
}



/*
 * Try to fetch the remote schedule right now, and create the recurring event
 * that will check for new schedules in the future.
 */
int enable_remote_schedule_fetch(wand_event_handler_t *ev_hdl,
        fetch_schedule_item_t *fetch) {

    schedule_item_t *item;

    assert(ev_hdl);

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
    item->ev_hdl = ev_hdl;
    item->data.fetch = fetch;

    /* create the timer event for fetching schedules */
    if ( wand_add_timer(ev_hdl, fetch->frequency, 0, item,
                timer_fetch_callback) == NULL ) {
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
#endif
