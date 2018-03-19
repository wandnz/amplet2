/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "youtube.h"
#include "youtube.pb-c.h"
#include "debug.h"
#include "dscp.h"
#include "usage.h"


static struct option long_options[] = {
    /* chromium arguments that we should pass through silently */
    {"headless", no_argument, 0, 0},
    {"type", required_argument, 0, 0},
    //{"no-zygote", no_argument, 0, 0},
    //{"no-sandbox", no_argument, 0, 0},

    /* actual test arguments that we need to deal with */
    {"quality", required_argument, 0, 'q'},
    {"youtube", required_argument, 0, 'y'},
    {"dscp", required_argument, 0, 'Q'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", optional_argument, 0, '4'},
    {"ipv6", optional_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {NULL, 0, 0, 0}
};



/*
 *
 */
static void usage(void) {
    fprintf(stderr,
        "Usage: amp-youtube [-hx] [-Q codepoint] [-Z interpacketgap]\n"
        "                   [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
        "                   [-q quality] -y video_id\n"
        "\n");

    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -q, --quality       <quality>  "
                "Suggested video quality, not guaranteed\n"
                "                      (small,medium,large,hd720,hd1080)\n");
    fprintf(stderr, "  -y, --youtube       <video_id> "
                "Youtube video ID to fetch\n");
    print_generic_usage();
}



/*
 * Check that the quality string matches a known video quality value.
 */
static int validate_quality(char *quality) {
    if ( quality == NULL ||
            strcmp(quality, "default") == 0 ||
            strcmp(quality, "small") == 0 ||
            strcmp(quality, "medium") == 0 ||
            strcmp(quality, "large") == 0 ||
            strcmp(quality, "hd720") == 0 ||
            strcmp(quality, "hd1080") == 0 ||
            strcmp(quality, "hd1440") == 0 ||
            strcmp(quality, "hd2160") == 0 ||
            strcmp(quality, "highres") == 0 ) {
        return 0;
    }

    return -1;
}



/*
 *
 */
static Amplet2__Youtube__Quality parse_quality(char *quality) {
    if ( quality == NULL || strcmp(quality, "default") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__DEFAULT;
    }

    if ( strcmp(quality, "small") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__SMALL;
    } else if ( strcmp(quality, "medium") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__MEDIUM;
    } else if ( strcmp(quality, "large") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__LARGE;
    } else if ( strcmp(quality, "hd720") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD720;
    } else if ( strcmp(quality, "hd1080") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD1080;
    } else if ( strcmp(quality, "hd1440") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD1440;
    } else if ( strcmp(quality, "hd2160") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD2160;
    } else if ( strcmp(quality, "highres") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HIGHRES;
    }

    printf("unknown quality '%s'\n", quality);
    return AMPLET2__YOUTUBE__QUALITY__UNKNOWN;
}



/*
 * Convert the video quality enum into a printable string.
 */
static char* print_quality(Amplet2__Youtube__Quality quality) {
    switch ( quality ) {
        case AMPLET2__YOUTUBE__QUALITY__DEFAULT: return "default";
        case AMPLET2__YOUTUBE__QUALITY__SMALL: return "small";
        case AMPLET2__YOUTUBE__QUALITY__MEDIUM: return "medium";
        case AMPLET2__YOUTUBE__QUALITY__LARGE: return "large";
        case AMPLET2__YOUTUBE__QUALITY__HD720: return "hd720";
        case AMPLET2__YOUTUBE__QUALITY__HD1080: return "hd1080";
        case AMPLET2__YOUTUBE__QUALITY__HD1440: return "hd1440";
        case AMPLET2__YOUTUBE__QUALITY__HD2160: return "hd2160";
        case AMPLET2__YOUTUBE__QUALITY__HIGHRES: return "highres";
        default: return "unknown";
    };
}



/*
 * Print statistics related to the video playback.
 */
static void print_video(Amplet2__Youtube__Item *video) {
    assert(video);

    printf("  Title: \"%s\"\n", video->title);
    printf("  Actual quality: %s\n", print_quality(video->quality));
    printf("  Reported duration: %0.3fs\n", video->reported_duration);
    printf("  Time before buffering: %lums\n", video->pre_time);
    printf("  Initial buffering: %lums\n", video->initial_buffering);
    printf("  Time playing: %lums\n", video->playing_time);
    if ( video->stall_count == 0 ) {
        printf("  Maintained continuous playback, did not stall\n");
    } else {
        printf("  Stalled %lu times for a total of %lums\n",
                video->stall_count, video->stall_time);
    }
    printf("  Total time: %lums\n", video->total_time);
}



/*
 * Construct a protocol buffer message containing the results for a video.
 */
static Amplet2__Youtube__Item* report_video_results(
        struct YoutubeTiming *info) {

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

    return video;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for the youtube video
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        struct YoutubeTiming *youtube, struct opt_t *opt) {

    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Amplet2__Youtube__Report msg = AMPLET2__YOUTUBE__REPORT__INIT;
    Amplet2__Youtube__Header header = AMPLET2__YOUTUBE__HEADER__INIT;

    header.video = opt->video;
    header.quality = parse_quality(opt->quality);
    header.has_quality = 1;
    header.dscp = opt->dscp;
    header.has_dscp = 1;

    msg.item = report_video_results(youtube);

    /* populate the top level report object with the header and servers */
    msg.header = &header;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__youtube__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__youtube__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    free(msg.item);

    return result;
}



/*
 * Main function to run the youtube test, returning a result structure that
 * will later be printed or sent across the network.
 */
amp_test_result_t* run_youtube(int argc, char *argv[],
        __attribute__((unused))int count,
        __attribute__((unused))struct addrinfo **dests) {
    int opt;
    int cpp_argc = 0;
    char *urlstr = NULL, *qualitystr = NULL;
    char *cpp_argv[5];
    struct YoutubeTiming *youtube;
    struct timeval start_time;
    struct opt_t options;

    memset(&options, 0, sizeof(struct opt_t));

    while ( (opt = getopt_long(argc, argv, "q:y:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4':
            case '6':
            case 'I': /* TODO --netifs-to-ignore works the opposite way */
            case 'Q':
                printf("UNIMPLEMENTED OPTION '-%c'\n", opt);
                break;
            case 'Z': /* not used, but might be set globally */ break;
            case 'q': options.quality = strdup(optarg); break;
            case 'v': print_package_version(argv[0]); exit(0);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            /* TODO there is also player.loadVideoByUrl() function, useful? */
            case 'y': options.video = strdup(optarg); break;
            case 0: /* TODO close stdout/stderr to hide chromium warnings? */
                      cpp_main(argc, (const char **)argv); break;
            case 'h':
            default: usage(); exit(0);
        };
    }

    /* if it's not a zygote process then it must set the video id */
    if ( options.video == NULL ) {
        Log(LOG_WARNING, "Missing youtube video id!\n");
        printf("-----2\n");
        usage();
        exit(-1);
    }

    /* check that the quality value is valid */
    if ( validate_quality(options.quality) < 0 ) {
        Log(LOG_WARNING, "Invalid quality value: %s\n", options.quality);
        printf("-----3\n");
        usage();
        exit(-1);
    }

    /* pass in --disable-gpu, one less process to worry about */
    cpp_argv[cpp_argc++] = argv[0];
    cpp_argv[cpp_argc++] = "--disable-gpu";

    /* command line parsing tools in chromium expect --key=value */
    if ( asprintf(&urlstr, "--youtube=%s", options.video) < 0 ) {
        Log(LOG_WARNING, "Failed to build youtube ID string, aborting\n");
        exit(-1);
    }
    cpp_argv[cpp_argc++] = urlstr;

    if ( options.quality != NULL ) {
        if ( asprintf(&qualitystr, "--quality=%s", options.quality) < 0 ) {
            Log(LOG_WARNING, "Failed to build quality string, aborting\n");
            exit(-1);
        }
        cpp_argv[cpp_argc++] = qualitystr;
    }

    cpp_argv[cpp_argc] = NULL;

    if ( gettimeofday(&start_time, NULL) != 0 ) {
        Log(LOG_ERR, "Could not gettimeofday(), aborting test");
        exit(-1);
    }

    /* run the browser */
    youtube = (struct YoutubeTiming*)cpp_main(cpp_argc,(const char**)cpp_argv);

    if ( urlstr ) {
        free(urlstr);
    }

    if ( qualitystr ) {
        free(qualitystr);
    }

    /* write the results to shared memory for the caller to read */
    if ( youtube ) {
        amp_test_result_t *result;
        char *filename;
        int fd;

        if ( asprintf(&filename, "/amp-youtube-%d", getpid()) < 0 ) {
            return NULL;
        }

        result = report_results(&start_time, youtube, &options);
        if ( (fd = shm_open(filename, O_RDWR|O_CREAT|O_EXCL, S_IRWXU)) < 0 ) {
            free(filename);
            return NULL;
        }

        free(filename);

        if ( write(fd, &result->timestamp, sizeof(result->timestamp)) !=
                sizeof(result->timestamp) ) {
            close(fd);
            return NULL;
        }
        if ( write(fd, &result->len, sizeof(result->len)) !=
                sizeof(result->len) ) {
            close(fd);
            return NULL;
        }
        if ( write(fd, result->data, result->len) != result->len ) {
            close(fd);
            return NULL;
        }
        close(fd);

        free(result->data);
        free(result);
    }

    return NULL;
}



/*
 * Print test results to stdout, nicely formatted for the standalone test.
 */
void print_youtube(amp_test_result_t *result) {
    Amplet2__Youtube__Report *msg;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__youtube__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    printf("AMP YouTube test, video: %s, desired quality: %s\n",
            msg->header->video, print_quality(msg->header->quality));
    print_video(msg->item);

    amplet2__youtube__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_YOUTUBE;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("youtube");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 300;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_youtube;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_youtube;

    /* the youtube test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the test a SIGINT warning, partial data isn't useful */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
/*
int amp_test_process_ipv4_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now) {
    return process_ipv4_packet(globals, packet, bytes, now);
}

amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt) {
    return report_results(start_time, count, info, opt);
}
*/
#endif
