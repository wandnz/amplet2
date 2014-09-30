#ifndef _MEASURED_SCHEDULE_H
#define _MEASURED_SCHEDULE_H

#include <stdint.h>
#include <libwandevent.h>
#include "tests.h" //TODO fix these names, test vs tests
#include "test.h"
#include "nametable.h"
#include "ampresolv.h"


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

/* convenience time conversions */
#define US_FROM_MS(x) (((x) % 1000)*1000)
#define MS_TRUNC(x)   (((int)(x)/1000)*1000)
#define S_FROM_MS(x)  ((int)((x)/1000))

#define MS_FROM_TV(tv) ((tv).tv_sec * 1000 + ((int)((tv).tv_usec / 1000)))

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
    struct timeval interval;	    /* time between test runs */
    uint64_t start;		    /* first time in period test can run (ms) */
    uint64_t end;		    /* last time in period test can run (ms) */
    schedule_period_t period;	    /* repeat cycle: Hourly, Daily, Weekly */
    test_type_t test_id;	    /* id of test to run */
    uint32_t dest_count;	    /* number of current destinations */
    uint32_t resolve_count;	    /* max possible count of dests to resolve */
    struct addrinfo **dests;	    /* all current destinations */
    resolve_dest_t *resolve;	    /* list of destination names to resolve */
    char **params;		    /* test parameters in execv format */
    /* TODO chaining? */

} test_schedule_item_t;



/*
 * Data block for limiting test event duration
 */
typedef struct kill_schedule_item {
    pid_t pid;			    /* pid of test process to kill */
    char *testname;                 /* name of the test to kill */
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
    EVENT_CANCEL_TEST,		    /* scheduled item is a watchdog */
    EVENT_RUN_TEST,		    /* scheduled item is a test */
    EVENT_FETCH_SCHEDULE,           /* scheduled item is a schedule fetch */
} event_type_t;

/*
 *
 */
typedef struct schedule_item {
    event_type_t type;		    /* type of schedule item (test, watchdog) */
    wand_event_handler_t *ev_hdl;   /* pointer to main event handler */
    union {
	test_schedule_item_t *test;
	kill_schedule_item_t *kill;
        fetch_schedule_item_t *fetch;
    } data;			    /* schedule item data based on type */
} schedule_item_t;


void clear_test_schedule(wand_event_handler_t *ev_hdl);
void read_schedule_dir(wand_event_handler_t *ev_hdl, char *directory);
void setup_schedule_refresh(wand_event_handler_t *ev_hdl);
struct timeval get_next_schedule_time(wand_event_handler_t *ev_hdl,
        schedule_period_t period, uint64_t start, uint64_t end,
        uint64_t frequency);
int update_remote_schedule(char *dir, char *server, char *cacert, char *cert,
        char *key);
void remote_schedule_callback(wand_event_handler_t *ev_hdl, void *data);
#if UNIT_TEST
time_t amp_test_get_period_max_value(char repeat);
int64_t amp_test_check_time_range(int64_t value, schedule_period_t period);
time_t amp_test_get_period_start(char repeat);
#endif

#endif
