#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <assert.h>
#include <glob.h>
#include <curl/curl.h>

#include <libwandevent.h>
#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "nametable.h"
#include "debug.h"
#include "modules.h"



/*
 * Dump a debug information line about a scheduled test.
 */
static void dump_event_run_test(test_schedule_item_t *item) {

    assert(item);

    printf("EVENT_RUN_TEST ");
    printf("%s %d.%.6d", amp_tests[item->test_id]->name,
	    (int)item->interval.tv_sec, (int)item->interval.tv_usec);

    if ( item->params == NULL ) {
	printf(" (no args)");
    } else {
        int i;
	/* params is a NULL terminated array */
	for ( i=0; item->params[i] != NULL; i++ ) {
	    printf(" %s", item->params[i]);
	}
    }
    printf("\n");
}



/*
 * Dump a debug information line about a scheduled watchdog to kill a test.
 */
static void dump_event_cancel_test(kill_schedule_item_t *item) {
    assert(item);

    printf("EVENT_CANCEL_TEST pid:%d\n", item->pid);
}



/*
 * Dump a debug information line about a scheduled watchdog to kill a test.
 */
static void dump_event_fetch_schedule(fetch_schedule_item_t *item) {
    assert(item);

    printf("EVENT_FETCH_SCHEDULE %s\n", item->schedule_url);
}



/*
 * Dump the current schedule for debug purposes
 */
static void dump_schedule(wand_event_handler_t *ev_hdl) {
    struct wand_timer_t *timer;
    schedule_item_t *item;

    printf("====== SCHEDULE ======\n");

    for ( timer=ev_hdl->timers; timer != NULL; timer=timer->next ) {
	printf("%d.%.6d ", (int)timer->expire.tv_sec,
		(int)timer->expire.tv_usec);
	if ( timer->data == NULL ) {
	    printf("NULL\n");
	    continue;
	}

	/* TODO add file refresh timers to this list */
	item = (schedule_item_t *)timer->data;
	switch ( item->type ) {
	    case EVENT_RUN_TEST: dump_event_run_test(item->data.test);
				 break;
	    case EVENT_CANCEL_TEST: dump_event_cancel_test(item->data.kill);
				    break;
            case EVENT_FETCH_SCHEDULE:
                                    dump_event_fetch_schedule(item->data.fetch);
                                    break;
	    default: printf("UNKNOWN\n"); continue;
	};
    }
    printf("\n");

}



/*
 * Free a test schedule item, as well as any parameters and pointers to
 * destinations it has.
 */
static void free_test_schedule_item(test_schedule_item_t *item) {

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
    if ( item->resolve != NULL ) {
	resolve_dest_t *tmp;
	for ( tmp=item->resolve; tmp != NULL; tmp=tmp->next ) {
	    if ( tmp->name != NULL ) {
		free(tmp->name);
	    }
	    /* this should be NULL, it is only populated in a forked test */
	    if ( tmp->addr != NULL ) {
		freeaddrinfo(tmp->addr);
	    }
	}
	free(item->resolve);
    }

    free(item);
}



/*
 * Walk the list of timers and remove all those that are scheduled tests.
 */
void clear_test_schedule(wand_event_handler_t *ev_hdl) {
    struct wand_timer_t *timer = ev_hdl->timers;
    struct wand_timer_t *tmp;
    schedule_item_t *item;

    while ( timer != NULL ) {
	tmp = timer;
	timer = timer->next;
	/*
	 * only remove future scheduled tests, need to leave any tasks that
	 * are watching currently executing tests
	 */
	if ( tmp->data != NULL ) {
	    item = (schedule_item_t *)tmp->data;
	    if ( item->type == EVENT_RUN_TEST ) {
		wand_del_timer(ev_hdl, tmp);
		if ( item->data.test != NULL ) {
		    free_test_schedule_item(item->data.test);
		}
		free(item);
		free(tmp);
	    }
	}
    }
}



/*
 * Convert the single "repeat" character from the schedule to the number of
 * seconds in that repeat period.
 */
static time_t get_period_max_value(char repeat) {
    switch ( repeat ) {
	case 'H': return 60*60;
	case 'D': return 60*60*24;
	case 'W': return 60*60*24*7;
	/*case 'M': return 60*60*24*31; */
	default: return -1;
    };
}



/*
 * Convert a scheduling number in a string to an integer, while also checking
 * that it fits within the limits of the schedule. This is used to convert
 * millisecond time values in the schedule for start, end, frequency.
 */
static int64_t get_time_value(char *value_string, char repeat) {
    int value;
    int max_interval;
    char *endptr;

    if ( value_string == NULL ) {
	return -1;
    }

    value = strtol(value_string, &endptr, 10);

    /* no number was found */
    if ( endptr == value_string ) {
	return -1;
    }

    /* don't accept any value that would overflow the time period */
    max_interval = (int)get_period_max_value(repeat) * 1000;

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
static time_t get_period_start(char repeat) {
    time_t now;
    struct tm period_start;

    time(&now);
    gmtime_r(&now, &period_start);
    period_start.tm_sec = 0;
    period_start.tm_min = 0;

    switch ( repeat ) {
	case 'H': /* time is already start of hour */ break;
	case 'D': period_start.tm_hour = 0; break;
	case 'W': period_start.tm_hour = 0;
		  period_start.tm_mday -= period_start.tm_wday;
		  break;
	/*
	case 'M': period_start.tm_hour = 0;
		  period_start.tm_mday = 1;
		  break;
	*/
	default: /* assume daily for now */ period_start.tm_hour = 0; break;
    };

    return timegm(&period_start);
}



/*
 * TODO do we need to check the parameters here, given they are going to be
 * used as part of the parameter array given to execv?
 */
static char **parse_param_string(char *param_string) {
    int i;
    char *tmp, *arg;
    char **result = (char**)malloc(sizeof(char*) * MAX_TEST_ARGS);

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
	char repeat, uint64_t start, uint64_t end, uint64_t frequency) {

    time_t period_start, period_end, test_end;
    struct timeval now, next = {0,0};
    int64_t diff;
    int next_repeat;

    period_start = get_period_start(repeat);
    test_end = (period_start*1000) + end;

    /*
     * now using wand_get_walltime() because it agrees better with the
     * monotonic clock. Using gettimeofday() was giving times a few
     * milliseconds behind what libwandevent thought they were, which was
     * causing tests to be rescheduled again in the same second.
     */
    //gettimeofday(&now, NULL);
    now = wand_get_walltime(ev_hdl);
    /* truncate to get current time of day to the millisecond level */
    now.tv_usec = MS_TRUNC(now.tv_usec);

    /* get difference in ms between the first event of this period and now */
    diff = now.tv_sec - period_start;
    diff *= 1000;
    diff += now.tv_usec / 1000;
    diff -= start;

    if ( diff < 0 ) {
	/* the start time hasn't been reached yet, so schedule for then */
	next.tv_sec = S_FROM_MS(abs(diff));
	next.tv_usec = US_FROM_MS(abs(diff));
	return next;
    }

    if ( frequency == 0 ) {
	/* if it's after the first and only event in the cycle, roll over */
	next_repeat = 1;
    } else {
	/* if it's after the first event but repeated, find the next repeat */
	next_repeat = 0;
	diff %= frequency;
	diff = frequency - diff;
	next.tv_sec = S_FROM_MS(diff);
	next.tv_usec = US_FROM_MS(diff);
    }

    /* check that this next repeat is allowed at this time */
    period_end = period_start + get_period_max_value(repeat);
    if ( next_repeat || now.tv_sec + S_FROM_MS(diff) > period_end ||
	    MS_FROM_TV(now) + diff > test_end ) {
	/* next time is after the end time for test, advance to next start */
	next.tv_sec = period_end - now.tv_sec;
        if ( now.tv_usec > 0 ) {
            next.tv_sec--;
            next.tv_usec = 1000000 - now.tv_usec;
        } else {
            next.tv_usec = 0;
        }
	ADD_TV_PARTS(next, next, S_FROM_MS(start), US_FROM_MS(start));
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

    if ( a->repeat != b->repeat )
	return 0;

    if ( a->start != b->start )
	return 0;

    if ( b->end != b->end )
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
    when = get_next_schedule_time(ev_hdl, item->repeat, item->start, item->end,
	    MS_FROM_TV(item->interval));
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
 * Read in the schedule file and create events for each test.
 *
 * TODO this is currently in the old schedule file format, do we want to update
 * or change this format at all?
 *
 * TODO better to use strtok or a scanf?
 */
static void read_schedule_file(wand_event_handler_t *ev_hdl, char *filename) {
    FILE *in;
    char line[MAX_SCHEDULE_LINE];
    struct wand_timer_t *timer = NULL;
    schedule_item_t *item = NULL;
    test_schedule_item_t *test = NULL;
    int lineno = 0;

    assert(ev_hdl);
    assert(filename);

    Log(LOG_INFO, "Loading schedule from %s", filename);

    if ( (in = fopen(filename, "r")) == NULL ) {
	Log(LOG_ALERT, "Failed to open schedule file %s: %s\n",
                filename, strerror(errno));
	exit(1);
    }

    while ( fgets(line, sizeof(line), in) != NULL ) {
	char *target, *testname, *repeat, *params;
	int64_t start, end, frequency;
	struct timeval next;
        nametable_t *addresses;
	test_type_t test_id;

	lineno++;

	/* ignore comments and blank lines */
	if ( line[0] == '#'  || line[0] == '\n' ) {
	    continue;
	}
	Log(LOG_DEBUG, "line=%s", line);

	/* read target,test,repeat,start,end,frequency,params */
	if ( (target = strtok(line, SCHEDULE_DELIMITER)) == NULL )
	    continue;
	if ( (testname = strtok(NULL, SCHEDULE_DELIMITER)) == NULL )
	    continue;
	if ( (repeat = strtok(NULL, SCHEDULE_DELIMITER)) == NULL )
	    continue;
	if ( (start = get_time_value(strtok(NULL, SCHEDULE_DELIMITER),
			repeat[0])) < 0 )
	    continue;
	if ( (end = get_time_value(strtok(NULL, SCHEDULE_DELIMITER),
			repeat[0])) < 0 )
	    continue;
	if ( (frequency = get_time_value(strtok(NULL, SCHEDULE_DELIMITER),
			repeat[0])) < 0 )
	    continue;
	params = strtok(NULL, SCHEDULE_DELIMITER);

	/* check test is valid */
	if ( (test_id = get_test_id(testname)) == AMP_TEST_INVALID ) {
	    Log(LOG_WARNING, "Unknown test '%s' on line %d", testname, lineno);
	    continue;
	}

	Log(LOG_DEBUG, "%s %s %s %ld %ld %ld %s", target, testname, repeat,
		start, end, frequency, (params)?params:"NULL");

	/* everything looks ok, populate the test info struct */
	test = (test_schedule_item_t *)malloc(sizeof(test_schedule_item_t));
	test->interval.tv_sec = S_FROM_MS(frequency);
	test->interval.tv_usec = US_FROM_MS(frequency);
	test->repeat = repeat[0];
	test->start = start;
	test->end = end;
	test->test_id = test_id;
	test->dests = NULL;
	test->resolve = NULL;
	test->resolve_count = 0;
	test->dest_count = 0;

	/* check if the destination is in the nametable */
        if ( (addresses = name_to_address(target)) != NULL ) {
            struct addrinfo *addr;
            int i = 0;
            /* add all the addresses in the addrinfo chain to the test */
            test->dests = (struct addrinfo **)malloc(
                    sizeof(struct addrinfo*) * addresses->count);
            for ( addr=addresses->addr; addr != NULL; addr=addr->ai_next ) {
                test->dests[i] = addr;
                i++;
            }
            test->dest_count = addresses->count;
	} else {
	    /* if it isn't then it will be resolved at test time */
	    char *count_str;

	    Log(LOG_DEBUG, "Unknown destination '%s' for %s test on line %d,"
		    " it will be resolved\n", target, testname, lineno);

	    test->resolve = (resolve_dest_t*)malloc(sizeof(resolve_dest_t));
	    test->resolve->name = strdup(strtok(target, ":"));
            test->resolve->family = AF_UNSPEC;
	    test->resolve->addr = NULL;
	    test->resolve->next = NULL;
            test->resolve_count = 1;    /* one name to resolve */
            test->resolve->count = 0;   /* resolve all address for name */
	    /*
	     * the schedule can determine how many addresses of what address
             * families are resolved:
	     * www.foo.com	-- resolve all addresses
	     * www.foo.com:1	-- resolve a single address
	     * www.foo.com:n	-- resolve up to n addresses
             * www.foo.com:v4   -- resolve all ipv4 addresses
             * www.foo.com:v6   -- resolve all ipv6 addresses
             * www.foo.com:n:v4 -- resolve up to n ipv4 addresses
             * www.foo.com:n:v6 -- resolve up to n ipv6 addresses
	     */
	    if ( (count_str=strtok(NULL, ":")) != NULL ) {
                do {
                    if (strncmp(count_str, "*", 1) == 0 ) {
                        /*
                         * Do nothing - backwards compatability with old
                         * schedules that defaulted to a single address and
                         * needed the * to resolve to all.
                         */
                    } else if ( strncmp(count_str, "v4", 2) == 0 ) {
                        test->resolve->family = AF_INET;
                    } else if ( strncmp(count_str, "v6", 2) == 0 ) {
                        test->resolve->family = AF_INET6;
                    } else {
                        test->resolve->count = atoi(count_str);
                    }
                } while ( (count_str=strtok(NULL, ":")) != NULL );
	    }
	}

	if ( params == NULL || strlen(params) < 1 ) {
	    test->params = NULL;
	} else {
	    test->params = parse_param_string(params);
        }

	/* if this test can have multiple target we may not need a new one */
	if ( amp_tests[test_id]->max_targets != 1 ) {
	    /* check if this test at this time already exists */
	    if ( merge_scheduled_tests(ev_hdl, test) ) {
		/* remove pointer to names, the merged test now owns it */
		test->resolve = NULL;
		/* free this test, it has now merged */
		free_test_schedule_item(test);
		continue;
	    }
	}

	Log(LOG_DEBUG, "Adding new test item for %s test\n", testname);

	/* schedule a new test */
	item = (schedule_item_t *)malloc(sizeof(schedule_item_t));
	item->type = EVENT_RUN_TEST;
	item->ev_hdl = ev_hdl;
	item->data.test = test;

	/* create the timer event for this test */
	timer = (struct wand_timer_t *)malloc(sizeof(struct wand_timer_t));
	timer->data = item;
	next = get_next_schedule_time(ev_hdl, repeat[0], start, end, frequency);
	timer->expire = wand_calc_expire(ev_hdl, next.tv_sec, next.tv_usec);
	timer->callback = run_scheduled_test;
	timer->prev = NULL;
	timer->next = NULL;
	wand_add_timer(ev_hdl, timer);
    }
    fclose(in);
}



/*
 *
 */
static void read_schedule_dir(wand_event_handler_t *ev_hdl, char *directory) {
    glob_t glob_buf;
    unsigned int i;
    char full_loc[MAX_PATH_LENGTH];

    assert(ev_hdl);
    assert(directory);
    assert(strlen(directory) < MAX_PATH_LENGTH - 8);

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
	read_schedule_file(ev_hdl, glob_buf.gl_pathv[i]);
    }

    dump_schedule(ev_hdl);

    globfree(&glob_buf);
    return;
}



/*
 *
 */
void remote_schedule_callback(struct wand_timer_t *timer) {
    schedule_item_t *item;
    fetch_schedule_item_t *data;
    pid_t pid;

    Log(LOG_DEBUG, "Timer fired for remote schedule checking");

    item = (schedule_item_t *)timer->data;
    assert(item->type == EVENT_FETCH_SCHEDULE);

    data = (fetch_schedule_item_t *)item->data.fetch;

    /* fork off a process to do the actual check */
    if ( (pid = fork()) < 0 ) {
        Log(LOG_WARNING, "Failed to fork for fetching remote schedule: %s",
                strerror(errno));
        return;
    } else if ( pid == 0 ) {
        if ( update_remote_schedule(data->schedule_dir, data->schedule_url,
                    data->cacert, data->cert, data->key) > 0 ) {
            /* send SIGUSR1 to parent to reload schedule */
            Log(LOG_DEBUG, "Sending SIGUSR1 to parent to reload schedule");
            kill(getppid(), SIGUSR1);
        }
        exit(0);
    }

    /* TODO should we have a watchdog on this task? */
    add_test_watchdog(item->ev_hdl, pid, SCHEDULE_FETCH_TIMEOUT,
            "Remote schedule fetch");

    /* reschedule checking for schedule updates */
    timer->expire = wand_calc_expire(item->ev_hdl, SCHEDULE_FETCH_FREQUENCY, 0);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(item->ev_hdl, timer);
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
int update_remote_schedule(char *dir, char *url, char *cacert, char *cert,
        char *key) {
    CURL *curl;

    Log(LOG_INFO, "Fetching remote schedule file from %s", url);

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
        snprintf(tmp_sched_file, MAX_PATH_LENGTH-1, "%s/%s", dir,
                TMP_REMOTE_SCHEDULE_FILE);
        tmp_sched_file[MAX_PATH_LENGTH-1] = '\0';

        snprintf(sched_file, MAX_PATH_LENGTH-1, "%s/%s", dir,
                REMOTE_SCHEDULE_FILE);
        sched_file[MAX_PATH_LENGTH-1] = '\0';

        /* Open the temporary file we read the remote schedule into */
        if ( (tmpfile = fopen(tmp_sched_file, "w")) == NULL ) {
            Log(LOG_WARNING, "Failed to open temporary schedule %s",
                    tmp_sched_file);
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
        curl_easy_setopt(curl, CURLOPT_FILETIME, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, tmpfile);
        /* get slightly more detailed error messages, useful with ssl */
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuf);

        /* use ssl if required (a good idea!) */
        if ( cacert != NULL && cert != NULL && key != NULL ) {
               Log(LOG_DEBUG, "CACERT=%s", cacert);
               Log(LOG_DEBUG, "KEY=%s", key);
               Log(LOG_DEBUG, "CERT=%s", cert);

                /* set the client cert and key that we present the server */
               curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
               curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);
               curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
               curl_easy_setopt(curl, CURLOPT_SSLKEY, key);

               /* set the CA cert that we validate the server against */
               curl_easy_setopt(curl, CURLOPT_CAINFO, cacert);

               /* Try to verify the certificate */
               curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
               /* Try to verify hostname/commonname */
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

        } else if ( stat_result == 0 ) {
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
        curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &cond_unmet);
        curl_easy_cleanup(curl);

        Log(LOG_DEBUG, "HTTP %ld Last-Modified:%d Length:%.0f",
                code, filetime, length);

        /* if a new file was fetched then move it into position */
        if ( code == 200 && cond_unmet == 0 && length > 0 ) {
            Log(LOG_INFO, "New schedule file fetched!");
            if ( rename(tmp_sched_file, sched_file) < 0 ) {
                Log(LOG_WARNING, "Error moving fetched schedule file %s to %s",
                        tmp_sched_file, sched_file);
                return -1;
            }
            return 1;
        }

        Log(LOG_INFO, "No new schedule file available");
        return 0;
    }

    Log(LOG_WARNING,
            "Failed to initialise curl, skipping fetch of remote schedule");
    return -1;
}

#if UNIT_TEST
time_t amp_test_get_period_max_value(char repeat) {
    return get_period_max_value(repeat);
}
int64_t amp_test_get_time_value(char *value_string, char repeat) {
    return get_time_value(value_string, repeat);
}
time_t amp_test_get_period_start(char repeat) {
    return get_period_start(repeat);
}
#endif
