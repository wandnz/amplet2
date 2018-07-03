/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2018 The University of Waikato, Hamilton, New Zealand.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "youtube.h"
#include "debug.h"
#include "youtube.pb-c.h"



/*
 * Construct a protocol buffer message containing the timeline of events that
 * took place during the video download and playback.
 */
static Amplet2__Youtube__Event* report_timeline_event(
        struct TimelineEvent *info) {
    Amplet2__Youtube__Event *event =
        (Amplet2__Youtube__Event*)malloc(sizeof(Amplet2__Youtube__Event));

    assert(info);
    assert(event);

    amplet2__youtube__event__init(event);
    event->has_timestamp = 1;
    event->timestamp = info->timestamp;
    event->has_type = 1;
    event->type = info->type;

    if ( event->type == AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY ) {
        event->has_quality = 1;
        event->quality = info->quality;
    }

    return event;
}



/*
 * Construct a protocol buffer message containing the results for a video.
 */
static Amplet2__Youtube__Item* report_video_results(
        struct YoutubeTiming *info) {

    unsigned int i;
    struct TimelineEvent *event;
    Amplet2__Youtube__Item *video =
        (Amplet2__Youtube__Item*)malloc(sizeof(Amplet2__Youtube__Item));

    assert(video);
    assert(info);

    amplet2__youtube__item__init(video);

    video->quality = info->quality;
    video->has_quality = 1;
    video->title = info->title;

    video->has_pre_time = 1;
    video->pre_time = info->pre_time;
    video->has_initial_buffering = 1;
    video->initial_buffering = info->initial_buffering;
    video->has_playing_time = 1;
    video->playing_time = info->playing_time;
    video->has_stall_time = 1;
    video->stall_time = info->stall_time;
    video->has_stall_count = 1;
    video->stall_count = info->stall_count;
    video->has_total_time = 1;
    video->total_time = info->total_time;
    video->has_reported_duration = 1;
    video->reported_duration = info->reported_duration;

    /* build up the repeated timeline section */
    video->n_timeline = info->event_count;
    video->timeline =
        malloc(sizeof(Amplet2__Youtube__Event*) * info->event_count);
    for ( i = 0, event = info->timeline;
            i < video->n_timeline && event != NULL;
            i++, event = event->next ) {
        video->timeline[i] = report_timeline_event(event);
    }

    return video;
}



/*
 *
 */
int main(int argc, char *argv[]) {
    struct YoutubeTiming *youtube;
    int i;

    /* TODO allow setting the log level to other values */
    /* need to reset log_level as it isn't carried over past the exec call */
    for ( i = 0; argv[i] != NULL; i++ ) {
        if ( strcmp(argv[i], "--debug") == 0 ) {
            log_level = LOG_DEBUG;
            log_level_override = 1;
            break;
        }
    }

    /* pass arguments and destinations through to the main test run function */
    youtube = cpp_main(argc, (const char**)argv);

    /* write the results to shared memory for the parent to examine */
    if ( youtube ) {
        Amplet2__Youtube__Item* result;
        char *filename;
        int fd;
        int buflen;
        void *buffer;

        /* results go into a file named after the test and pid */
        if ( asprintf(&filename, "/amp-youtube-%d", getpid()) < 0 ) {
            Log(LOG_WARNING, "Failed to create filename");
            exit(EXIT_FAILURE);
        }

        /* pack the video result protobuf message and write to shared memory */
        result = report_video_results(youtube);
        buflen = amplet2__youtube__item__get_packed_size(result);
        buffer = calloc(1, buflen);
        amplet2__youtube__item__pack(result, buffer);

        Log(LOG_DEBUG, "writing results to shared memory: %s", filename);

        if ( (fd = shm_open(filename, O_RDWR|O_CREAT|O_EXCL, S_IRWXU)) < 0 ) {
            free(filename);
            Log(LOG_WARNING, "Failed to open shared file");
            exit(EXIT_FAILURE);
        }

        free(filename);

        if ( write(fd, &buflen, sizeof(buflen)) != sizeof(buflen) ) {
            close(fd);
            Log(LOG_WARNING, "Failed to write length");
            exit(EXIT_FAILURE);
        }

        if ( write(fd, buffer, buflen) != buflen ) {
            close(fd);
            Log(LOG_WARNING, "Failed to write data");
            exit(EXIT_FAILURE);
        }

        close(fd);

        free(buffer);

        exit(EXIT_SUCCESS);
    }

    Log(LOG_DEBUG, "No data reported by chromium process");

    exit(EXIT_FAILURE);
}
