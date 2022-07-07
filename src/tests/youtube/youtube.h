/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2022 The University of Waikato, Hamilton, New Zealand.
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

#ifndef _TESTS_YOUTUBE_H
#define _TESTS_YOUTUBE_H

#include <sys/types.h>
#include <stdint.h>
#include <sys/time.h>

#include "testlib.h"
#include "youtube.pb-c.h"

/* convenience for extracting values from json objects */
#define JSON_INT(json, name) (json_integer_value(json_object_get(json, name)))
#define JSON_STR(json, name) (json_string_value(json_object_get(json, name)))

#define MAX_RETRY_ATTEMPTS 3
#define DEFAULT_DEVTOOLS_PORT 9222

char *chromium_paths[] = {
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome",
    NULL,
};

char *firefox_paths[] = {
    "/usr/bin/firefox",
    NULL,
};

char *chromium_argv[] = {
    "chromium",
    "--headless",
    "--no-sandbox",
    "--disable-dev-shm",
    "--mute-audio",
    NULL,
    NULL
};

/*
 * XXX firefox won't do anything on the remote debugging connection after
 * calling Page.navigate for the first time? So navigate to a page as part
 * of starting up the browser, and it will then work once we connect. Is
 * this a firefox bug or am I using it wrong?
 */
char *firefox_argv[] = {
    "firefox",
    "--headless",
    NULL,
    "file://",
    NULL
};

/*
 * User defined test options.
 */
struct test_options {
    char *video;
    char *quality;
    char *useragent;
    int forcev4;                                /* force use of ipv4 */
    int forcev6;                                /* force use of ipv6 */
    char *device;                               /* source device name */
    char *sourcev4;                             /* source v4 address */
    char *sourcev6;                             /* source v6 address */
    uint8_t dscp;
    uint16_t maxruntime;                        /* max video duration */
    int run_browser;                            /* start a new browser */
    int port;                                   /* devtools port */
    Amplet2__Youtube__Browser browser;          /* browser type */
};

/* command queue for messages to the browser */
struct command {
    char *method;
    char *params;
    struct command *next;
};

struct TimelineEvent {
    uint64_t timestamp;
    Amplet2__Youtube__EventType type;
    Amplet2__Youtube__Quality quality;
};

struct YoutubeTiming {
    char *video;
    char *title;
    Amplet2__Youtube__Quality quality;
    uint64_t initial_buffering;
    uint64_t playing_time;
    uint64_t stall_time;
    uint64_t stall_count;
    uint64_t total_time;
    uint64_t pre_time;
    uint64_t reported_duration;
    uint64_t event_count;
    struct TimelineEvent *timeline;
};


amp_test_result_t* run_youtube(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_youtube(amp_test_result_t *result);
test_t *register_test(void);

#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        struct YoutubeTiming *stats, struct test_options *opt);
#endif

#endif
