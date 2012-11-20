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

#if HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

#include <libwandevent.h>
#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "nametable.h"
#include "debug.h"



/*
 * Dump a debug information line about a scheduled test.
 */
static void dump_event_run_test(test_schedule_item_t *item) {
    int i;

    assert(item);

    printf("EVENT_RUN_TEST ");
    printf("%s %d.%.6d", amp_tests[item->test_id]->name, 
	    (int)item->interval.tv_sec, (int)item->interval.tv_usec);

    if ( item->params == NULL ) {
	printf(" (no args)");
    } else {
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

    printf("EVENT_CANCEL_TEST pid:%d", item->pid);
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

	item = (schedule_item_t *)timer->data;
	switch ( item->type ) {
	    case EVENT_RUN_TEST: dump_event_run_test(item->data.test); 
				 break;
	    case EVENT_CANCEL_TEST: dump_event_cancel_test(item->data.kill); 
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
    int i;

    /* free any test parameters, NULL terminated array */
    if ( item->params != NULL ) {
	for ( i=0; item->params[i] != NULL; i++ ) {
	    free(item->params[i]);
	}
	free(item->params);
    }
    /* free the pointers to destinations, but not the destinations themselves */
    free(item->dests);
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



#if HAVE_SYS_INOTIFY_H
/*
 * inotify tells us the file has changed, so consume the event, clear the
 * existing schedule and load the new one.
 *
 * inotify is only available on Linux.
 */
static void schedule_file_changed_event(struct wand_fdcb_t *evcb,
	__attribute__((unused)) enum wand_eventtype_t ev) {
    struct inotify_event buf;
    schedule_file_data_t *data = (schedule_file_data_t *)evcb->data;

    if ( read(data->fd, &buf, sizeof(buf)) == sizeof(buf) ) {
	/* make sure this is a file modify event, if so, reread schedules */
	if ( buf.mask & IN_MODIFY ) {
	    clear_test_schedule(data->ev_hdl);
	    read_schedule_file(data->ev_hdl);
	}
    }
}



/* 
 * Set up inotify to monitor the schedule file for changes. Give the file
 * descriptor that we get from inotify_add_watch() to libwandevent to monitor
 * so that we can run the callback function schedule_file_changed_event()
 * when the file changes.
 *
 * inotify is only available on Linux.
 */
static void setup_schedule_refresh_inotify(wand_event_handler_t *ev_hdl) {
    int inotify_fd;
    int schedule_wd;
    struct wand_fdcb_t *schedule_watch_ev;
    schedule_file_data_t *schedule_data;

    Log(LOG_DEBUG, "Using inotify to monitor schedule file");
    
    schedule_watch_ev = (struct wand_fdcb_t*)malloc(sizeof(struct wand_fdcb_t));
    schedule_data = (schedule_file_data_t*)malloc(sizeof(schedule_file_data_t));
    
    if ( (inotify_fd = inotify_init()) < 0 ) {
	perror("inotify_init");
	exit(1);
    }

    /* create a watch for modification of the schedule file */
    if ( (schedule_wd = 
		inotify_add_watch(inotify_fd, SCHEDULE_FILE, IN_MODIFY)) < 0 ) {
	perror("inotify_add_watch");
	exit(1);
    }

    /* save inotify_fd so we can read from it later */
    schedule_data->fd = inotify_fd;
    schedule_data->ev_hdl = ev_hdl;
    /* schedule event on the inotify_fd being available for reading */
    schedule_watch_ev->data = schedule_data;
    schedule_watch_ev->fd = inotify_fd;
    schedule_watch_ev->flags = EV_READ;
    schedule_watch_ev->callback = schedule_file_changed_event;
    wand_add_event(ev_hdl, schedule_watch_ev);
}

#else

/*
 * Check if the schedule file has been modified since the last check. If it
 * has then this invalidates all currently scheduled tests (which will need to
 * be cleared). The file needs to be read and the new tests added to the
 * schedule.
 *
 * TODO do we care about the file changing multiple times a second?
 */
static void check_schedule_file(struct wand_timer_t *timer) {
    schedule_file_data_t *data = (schedule_file_data_t *)timer->data;
    struct stat statInfo;
    time_t now;
    
    /* check if the schedule file has changed since last time */
    now = time(NULL);
    if ( stat(SCHEDULE_FILE, &statInfo) != 0 ) {
	perror("error statting schedule file");
	exit(1);
    }

    if ( statInfo.st_mtime > data->last_update ) {
	/* clear out all events and add new ones */
	Log(LOG_INFO, "Schedule file modified, updating\n");
	clear_test_schedule(data->ev_hdl);
	read_schedule_file(data->ev_hdl);
	data->last_update = statInfo.st_mtime;
	Log(LOG_INFO, "Done updating schedule file\n");
    }
    
    /* reschedule the check again */
    timer->expire = wand_calc_expire(data->ev_hdl, SCHEDULE_CHECK_FREQ, 0);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(data->ev_hdl, timer);
}



/* 
 * set up a libwandevent timer to monitor the schedule file for changes 
 */
static void setup_schedule_refresh_timer(wand_event_handler_t *ev_hdl) {
    struct wand_timer_t *schedule_timer;
    schedule_file_data_t *schedule_data;
    
    Log(LOG_DEBUG, "Using polling to monitor schedule file (interval: %ds)", 
	    SCHEDULE_CHECK_FREQ);

    schedule_timer = (struct wand_timer_t*)malloc(sizeof(struct wand_timer_t));
    schedule_data = (schedule_file_data_t*)malloc(sizeof(schedule_file_data_t));

    /* record now as the time it was last updated */
    schedule_data->last_update = time(NULL);
    schedule_data->ev_hdl = ev_hdl;
    /* schedule another read of the file in 60 seconds */
    schedule_timer->expire = wand_calc_expire(ev_hdl, SCHEDULE_CHECK_FREQ, 0);
    schedule_timer->callback = check_schedule_file;
    schedule_timer->data = schedule_data;
    schedule_timer->prev = NULL;
    schedule_timer->next = NULL;
    wand_add_timer(ev_hdl, schedule_timer);
}

#endif



/*
 * Set up an event to monitor the schedule file for changes. Use inotify if it
 * is available (Linux only) to immediately be alerted of changes, otherwise
 * poll the schedule file to check for changes.
 */
void setup_schedule_refresh(wand_event_handler_t *ev_hdl) {
#if HAVE_SYS_INOTIFY_H
    /* use inotify if we are on linux, it is nicer and quicker */
    setup_schedule_refresh_inotify(ev_hdl);
#else
    /* if missing inotify then use libwandevent timers to check regularly */
    setup_schedule_refresh_timer(ev_hdl);
#endif
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
static long get_time_value(char *value_string, char repeat) {
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
    struct timeval now, next;
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
	next.tv_usec = 0;
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
    int i;

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
	for ( i=0; a->params[i] != NULL && b->params != NULL; i++ ) {
	    if ( strcmp(a->params[i], b->params[i]) != 0 )
		return 0;
	}
    }
    
    /* if either isn't null by now then the params lists are different */
    if ( a->params[i] != NULL || b->params[i] != NULL )
	return 0;

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
	    if ( sched_test->dest_count < 
		    amp_tests[item->test_id]->max_targets ) {

		fprintf(stderr, "merging tests\n");

		/* 
	 	 * resize the dests pointers to make room for the new dest
		 * TODO be smarter about resizing
		 */
		sched_test->dests = realloc(sched_test->dests, 
			(sched_test->dest_count+1) * sizeof(struct addrinfo *));
		sched_test->dests[sched_test->dest_count++] = item->dests[0];
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
 * TODO maybe a config dir similar to apache enable-sites etc? read everything
 * in that dir as a config file and then we can turn things on and off easily,
 * or add new tests without having to edit/transfer a monolithic file.
 *
 * TODO how to deal with multiple tests at the same time that can handle
 * multiple destinations? Do we want to keep a list of all the tests so
 * that we can add multiple destinations to a single instance at the time of
 * reading the config? At the point of calling the test we don't know what
 * other tests are about to trigger.
 *
 * TODO better to use strtok or a scanf?
 */
void read_schedule_file(wand_event_handler_t *ev_hdl) {
    FILE *in;
    char line[MAX_SCHEDULE_LINE];
    struct wand_timer_t *timer = NULL;
    schedule_item_t *item = NULL;
    test_schedule_item_t *test = NULL;
    int lineno = 0;

    Log(LOG_INFO, "Loading schedule from %s", SCHEDULE_FILE);

    if ( (in = fopen(SCHEDULE_FILE, "r")) == NULL ) {
	perror("error opening schedule file");
	exit(1);
    }

    while ( fgets(line, sizeof(line), in) != NULL ) {
	char *target, *testname, *repeat, *params;
	long start, end, frequency;
	struct timeval next;
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
	
	/* check target is valid */
	if ( name_to_address(target) == NULL ) {
	    Log(LOG_WARNING, 
		    "Unknown destination '%s' for %s test on line %d\n", 
		    target, testname, lineno);
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
	test->dests = (struct addrinfo **)malloc(sizeof(struct addrinfo*));
	*test->dests = name_to_address(target);
	test->dest_count = 1;
	if ( params == NULL || strlen(params) < 1 )
	    test->params = NULL;
	else
	    test->params = parse_param_string(params);
	
	/* if this test can have multiple target we may not need a new one */
	if ( amp_tests[test_id]->max_targets > 1 ) {
	    /* check if this test at this time already exists */
	    if ( merge_scheduled_tests(ev_hdl, test) ) {
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
    dump_schedule(ev_hdl);
}
