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



/*
 * Walk the list of timers and remove all those that are scheduled tests.
 */
static void clear_test_schedule(wand_event_handler_t *ev_hdl) {
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
		    free(item->data.test);
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
 */
static void schedule_file_changed_event(struct wand_fdcb_t *evcb,
	__attribute__((unused)) enum wand_eventtype_t ev) {
    struct inotify_event buf;
    schedule_file_data_t *data = (schedule_file_data_t *)evcb->data;

    if ( read(data->fd, &buf, sizeof(buf)) == sizeof(buf) ) {
	if ( buf.mask & IN_MODIFY ) {
	    clear_test_schedule(data->ev_hdl);
	    read_schedule_file(data->ev_hdl);
	}
    }
}



/* 
 * set up inotify to monitor the schedule file for changes 
 */
static void setup_schedule_refresh_inotify(wand_event_handler_t *ev_hdl) {
    int inotify_fd;
    int schedule_wd;
    struct wand_fdcb_t *schedule_watch_ev;
    schedule_file_data_t *schedule_data;
    
    schedule_watch_ev = (struct wand_fdcb_t*)malloc(sizeof(struct wand_fdcb_t));
    schedule_data = (schedule_file_data_t*)malloc(sizeof(schedule_file_data_t));
    
    if ( (inotify_fd = inotify_init()) < 0 ) {
	perror("inotify_init");
	exit(1);
    }

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
	fprintf(stderr, "Schedule file modified, updating\n");
	clear_test_schedule(data->ev_hdl);
	read_schedule_file(data->ev_hdl);
	data->last_update = statInfo.st_mtime;
	fprintf(stderr, "Done updating schedule file\n");
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
 *
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
 * that it fits within the limits of the schedule.
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
 * Calculate the next time that a test is due to be run and return a timeval
 * with an offset appropriate for use with libwandevent scheduling. We have to
 * use an offset because libwandevent schedules relative to a monotonic clock,
 * not the system clock.
 *
 * TODO what sizes do we want to use for time values?
 */
struct timeval get_next_schedule_time(char repeat, uint64_t start,
	uint64_t end, uint64_t frequency) {

    time_t period_start, period_end, test_end;
    struct timeval now, next;
    int64_t diff;
    int next_repeat;

    period_start = get_period_start(repeat);
    test_end = (period_start*1000) + end;

    /* truncate to get current time of day to the millisecond level */
    gettimeofday(&now, NULL);
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
    fprintf(stderr, "scheduled: %d.%d\n", (int)next.tv_sec, (int)next.tv_usec);
    return next;
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

    if ( (in = fopen(SCHEDULE_FILE, "r")) == NULL ) {
	perror("error opening schedule file");
	exit(1);
    }

    while ( fgets(line, sizeof(line), in) != NULL ) {
	char *target, *testname, *repeat, *params;
	long start, end, frequency;
	struct timeval next;

	/* ignore comments and blank lines */
	if ( line[0] == '#'  || line[0] == '\n' ) {
	    continue;
	}
	printf("line=%s", line);

	/* read target,test,repeat,start,end,frequency,params */
	if ( (target = strtok(line, ",")) == NULL )
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

	/* TODO check target is valid */

	/* TODO check test is valid */

	/* TODO check params are valid */


	printf("%s %s %s %ld %ld %ld %s\n", target, testname, repeat, start, 
		end, frequency, (params)?params:"NULL");

	/* everything looks ok, populate the test info struct */
	test = (test_schedule_item_t *)malloc(sizeof(test_schedule_item_t));
	test->interval.tv_sec = S_FROM_MS(frequency);
	test->interval.tv_usec = US_FROM_MS(frequency);
	test->repeat = repeat[0];
	test->start = start;
	test->end = end;
	
	item = (schedule_item_t *)malloc(sizeof(schedule_item_t));
	item->type = EVENT_RUN_TEST;
	item->ev_hdl = ev_hdl;
	item->data.test = test;
	
	/* create the timer event for this test */
	timer = (struct wand_timer_t *)malloc(sizeof(struct wand_timer_t));
	timer->data = item;
	next = get_next_schedule_time(repeat[0], start, end, frequency);
	timer->expire = wand_calc_expire(ev_hdl, next.tv_sec, next.tv_usec);
	timer->callback = run_scheduled_test;
	timer->prev = NULL;
	timer->next = NULL;
	wand_add_timer(ev_hdl, timer);
    }
    fclose(in);
}
