#ifndef _MEASURED_SCHEDULE_H
#define _MEASURED_SCHEDULE_H

#include <stdint.h>
#include <libwandevent.h>
#include "tests.h" //TODO fix these names, test vs tests
#include "test.h"
#include "ampresolv.h"

/* debug schedule output file location */
#define DEBUG_SCHEDULE_DUMP_FILE "/tmp/amplet2.schedule.dump"

/* maximum line length for a single schedule line */
#define MAX_SCHEDULE_LINE 1024
/* character delimiting fields in the schedule file */
#define SCHEDULE_DELIMITER ","

/* TODO move config file defines elsewhere, point at sensible places */
//#define AMP_CONFIG_DIR "/tmp/brendonj"
#define SCHEDULE_DIR AMP_CONFIG_DIR "/schedules"
#define REMOTE_SCHEDULE_FILE "/fetched.sched"
#define TMP_REMOTE_SCHEDULE_FILE "/.fetched.sched.tmp"
#define SCHEDULE_FETCH_FREQUENCY 3600
#define SCHEDULE_FETCH_TIMEOUT 30
//#define AMP_TEST_DIRECTORY AMP_CONFIG_DIR "/tests/"
#define MAX_TEST_ARGS 128

/* tests can start at most 500ms (in usec) early, otherwise reschedule them */
#define SCHEDULE_CLOCK_FUDGE ( 500 * 1000 )

/* convenience time conversions */
#define US_FROM_MS(x) (((x) % 1000)*1000)
#define MS_TRUNC(x)   (((int)(x)/1000)*1000)
#define S_FROM_MS(x)  ((int)((x)/1000))

#define MS_FROM_TV(tv) ((tv).tv_sec * 1000 + ((int)((tv).tv_usec / 1000)))
#define US_FROM_TV(tv) ((tv).tv_sec * INT64_C(1000000) + ((int64_t)((tv).tv_usec)))

#define ADD_TV_PARTS(res, opa, opsec, opus) {\
    (res).tv_sec  = (opa).tv_sec  + (opsec); \
    (res).tv_usec = (opa).tv_usec + (opus); \
    while ( (res).tv_usec >= 1000000 ) {  \
	(res).tv_usec -= 1000000; \
	(res).tv_sec  += 1; \
    } \
}


typedef enum schedule_period {
    SCHEDULE_PERIOD_INVALID,
    SCHEDULE_PERIOD_HOURLY,
    SCHEDULE_PERIOD_DAILY,
    SCHEDULE_PERIOD_WEEKLY,
} schedule_period_t;


/*
 * Data block for scheduled test events.
 */
typedef struct test_schedule_item {
    struct timeval abstime;         /* time the next test is inteded to run */
    struct timeval interval;	    /* time between test runs */
    uint64_t start;		    /* first time in period test can run (ms) */
    uint64_t end;		    /* last time in period test can run (ms) */
    schedule_period_t period;	    /* repeat cycle: Hourly, Daily, Weekly */
    test_type_t test_id;	    /* id of test to run */
    uint32_t dest_count;	    /* number of current destinations */
    uint32_t resolve_count;	    /* max possible count of dests to resolve */
    struct addrinfo **dests;	    /* all current destinations */
    resolve_dest_t *resolve;	    /* list of destination names to resolve */
    amp_test_meta_t *meta;          /* which interface/addresses to use */
    char **params;		    /* test parameters in execv format */
    /* TODO chaining? */

} test_schedule_item_t;



/*
 * Data block for limiting test event duration
 */
typedef struct kill_schedule_item {
    pid_t pid;			    /* pid of test process to kill */
    char *testname;                 /* name of the test to kill */
    uint8_t sigint;                 /* should we send a SIGINT warning shot */
} kill_schedule_item_t;



/*
 * Data block for fetching remote schedule files.
 */
typedef struct fetch_schedule_item {
    char *schedule_dir;
    char *schedule_url;
    char *cacert;
    char *cert;
    char *key;
    int frequency;
} fetch_schedule_item_t;

/*
 *
 */
typedef enum {
    EVENT_RUN_TEST,		    /* scheduled item is a test */
    EVENT_FETCH_SCHEDULE,           /* scheduled item is a schedule fetch */
} event_type_t;

/*
 *
 */
typedef struct schedule_item {
    event_type_t type;		    /* type of schedule item (test, fetch) */
    wand_event_handler_t *ev_hdl;   /* pointer to main event handler */
    union {
	test_schedule_item_t *test;
	kill_schedule_item_t *kill;
        fetch_schedule_item_t *fetch;
    } data;			    /* schedule item data based on type */
} schedule_item_t;


char **parse_param_string(char *param_string);
char **populate_target_lists(test_schedule_item_t *test, char **targets);
void dump_schedule(wand_event_handler_t *ev_hdl, FILE *out);
void clear_test_schedule(wand_event_handler_t *ev_hdl, int all);
void read_schedule_dir(wand_event_handler_t *ev_hdl, char *directory,
        amp_test_meta_t *meta);
struct timeval get_next_schedule_time(wand_event_handler_t *ev_hdl,
        schedule_period_t period, uint64_t start, uint64_t end,
        uint64_t frequency, int run, struct timeval *abstime);
void signal_fetch_callback(wand_event_handler_t *ev_hdl, int signum,void *data);
int enable_remote_schedule_fetch(wand_event_handler_t *ev_hdl,
        fetch_schedule_item_t *fetch);
#if UNIT_TEST
time_t amp_test_get_period_max_value(char repeat);
int64_t amp_test_check_time_range(int64_t value, schedule_period_t period);
time_t amp_test_get_period_start(char repeat, time_t *now);
#endif

#endif
