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

#ifndef _MEASURED_SCHEDULE_H
#define _MEASURED_SCHEDULE_H

#include <stdint.h>
#include <libwandevent.h>
#include "tests.h"
#include "ampresolv.h"

/* debug schedule output file location */
#define DEBUG_SCHEDULE_DUMP_FILE "/tmp/amplet2.schedule.dump"

/* maximum line length for a single schedule line */
#define MAX_SCHEDULE_LINE 1024
/* character delimiting fields in the schedule file */
#define SCHEDULE_DELIMITER ","

/* TODO move config file defines elsewhere, point at sensible places */
#define SCHEDULE_DIR AMP_CONFIG_DIR "/schedules"
#define REMOTE_SCHEDULE_FILE "/fetched.sched"
#define TMP_REMOTE_SCHEDULE_FILE "/.fetched.sched.tmp"
#define SCHEDULE_FETCH_FREQUENCY 3600
#define SCHEDULE_FETCH_TIMEOUT 30
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
 * Test meta information - interfaces, timing, addresses etc to use.
 */
typedef struct amp_test_meta {
    char *interface;
    char *sourcev4;
    char *sourcev6;
    char *ampname;
    uint32_t inter_packet_delay;
    uint8_t dscp;
} amp_test_meta_t;


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
