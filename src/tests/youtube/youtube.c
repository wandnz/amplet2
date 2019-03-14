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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <assert.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "youtube.h"
#include "youtube.pb-c.h"
#include "debug.h"
#include "dscp.h"
#include "usage.h"


static struct option long_options[] = {
    {"quality", required_argument, 0, 'q'},
    {"useragent", required_argument, 0, 'a'},
    {"user-agent", required_argument, 0, 'a'},
    {"youtube", required_argument, 0, 'y'},
    {"max-runtime", required_argument, 0, 't'},
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
        "                   [-a useragent] [-t max-runtime] [-q quality]\n"
        "                   -y video_id\n"
        "\n");

    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --useragent     <useragent> "
                "Override browser User-Agent string\n");
    fprintf(stderr, "  -q, --quality       <quality>   "
                "Suggested video quality, not guaranteed\n"
                "           (default,small,medium,large,hd720,hd1080,hd1440,hd2160,highres)\n");
    fprintf(stderr, "  -t, --max-runtime   <seconds>  "
                "Maximum duration of video playback\n");
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

    Log(LOG_WARNING, "Unknown quality '%s'", quality);
    return AMPLET2__YOUTUBE__QUALITY__UNKNOWN;
}



/*
 * Convert the video quality enum into a printable string.
 */
static char* get_quality_string(Amplet2__Youtube__Quality quality) {
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



static char* get_event_string(Amplet2__Youtube__EventType event) {
    switch ( event ) {
        case AMPLET2__YOUTUBE__EVENT_TYPE__READY: return "ready";
        case AMPLET2__YOUTUBE__EVENT_TYPE__UNSTARTED: return "unstarted";
        case AMPLET2__YOUTUBE__EVENT_TYPE__BUFFERING: return "buffering";
        case AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY: return "quality change";
        case AMPLET2__YOUTUBE__EVENT_TYPE__PLAYING: return "playing";
        case AMPLET2__YOUTUBE__EVENT_TYPE__ENDED: return "ended";
        default: return "unknown";
    };
}


static void print_timeline_event(Amplet2__Youtube__Event *event) {
    printf("    %8" PRIu64 "ms", event->timestamp);
    printf(" %s", get_event_string(event->type));
    if ( event->type == AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY &&
            event->has_quality ) {
        printf(" (%s)", get_quality_string(event->quality));
    }
    printf("\n");
}



/*
 * Print statistics related to the video playback.
 */
static void print_video(Amplet2__Youtube__Item *video) {
    unsigned int i;

    assert(video);

    printf("  Title: \"%s\"\n", video->title);
    printf("  Final quality: %s\n", get_quality_string(video->quality));
    printf("  Reported duration: %lums\n", video->reported_duration);
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
    printf("  Timeline:\n");
    for ( i = 0; i < video->n_timeline; i++ ) {
        print_timeline_event(video->timeline[i]);
    }
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for the youtube video
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        Amplet2__Youtube__Item *youtube, struct opt_t *opt) {

    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Amplet2__Youtube__Report msg = AMPLET2__YOUTUBE__REPORT__INIT;
    Amplet2__Youtube__Header header = AMPLET2__YOUTUBE__HEADER__INIT;

    header.video = opt->video;
    header.quality = parse_quality(opt->quality);
    header.has_quality = 1;
    header.dscp = opt->dscp;
    header.has_dscp = 1;
    header.useragent = opt->useragent;
    header.has_maxruntime = 1;
    header.maxruntime = opt->maxruntime;

    msg.item = youtube;

    /* populate the top level report object with the header and servers */
    msg.header = &header;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__youtube__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__youtube__report__pack(&msg, result->data);

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
    char *urlstr = NULL;
    char *qualitystr = NULL;
    char *useragentstr = NULL;
    char *runtimestr = NULL;
    char *cpp_argv[10];
    Amplet2__Youtube__Item *youtube;
    struct timeval start_time;
    struct opt_t options;
    int pid;
    int fd;
    int status;
    char *filename;
    amp_test_result_t *result;
    void *buffer;
    int buflen;
    extern char **environ;

    memset(&options, 0, sizeof(struct opt_t));

    /* TODO get chromium version from chromium libraries */
    options.useragent = "AMP YouTube test agent (Chromium 71.0.3578.98)";

    while ( (opt = getopt_long(argc, argv, "a:q:t:y:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4':
            case '6':
            case 'I': /* TODO --netifs-to-ignore works the opposite way */
            case 'Q':
                Log(LOG_WARNING, "UNIMPLEMENTED OPTION '-%c'", opt);
                break;
            case 'Z': /* not used, but might be set globally */ break;
            case 'a': options.useragent = optarg; break;
            case 'q': options.quality = optarg; break;
            case 't': options.maxruntime = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            /* TODO there is also player.loadVideoByUrl() function, useful? */
            case 'y': options.video = optarg; break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    /* if it's not a zygote process then it must set the video id */
    if ( options.video == NULL ) {
        Log(LOG_WARNING, "Missing youtube video id!\n");
        usage();
        exit(EXIT_FAILURE);
    }

    /* check that the quality value is valid */
    if ( validate_quality(options.quality) < 0 ) {
        Log(LOG_WARNING, "Invalid quality value: %s\n", options.quality);
        usage();
        exit(EXIT_FAILURE);
    }

    /* pass in --disable-gpu, one less process to worry about */
    cpp_argv[cpp_argc++] = argv[0];
    cpp_argv[cpp_argc++] = "--disable-gpu";
    /* get rid of all the extra processes */
    //cpp_argv[cpp_argc++] = "--single-process";
    //cpp_argv[cpp_argc++] = "--no-zygote";
    cpp_argv[cpp_argc++] = "--no-sandbox";
    cpp_argv[cpp_argc++] = "--disable-audio-output";

    /* TODO allow setting the log level to other values */
    if ( log_level == LOG_DEBUG ) {
        cpp_argv[cpp_argc++] = "--debug";
    }

    /* command line parsing tools in chromium expect --key=value */
    if ( asprintf(&urlstr, "--youtube=%s", options.video) < 0 ) {
        Log(LOG_WARNING, "Failed to build youtube ID string, aborting\n");
        exit(EXIT_FAILURE);
    }
    cpp_argv[cpp_argc++] = urlstr;

    if ( options.quality != NULL ) {
        if ( asprintf(&qualitystr, "--quality=%s", options.quality) < 0 ) {
            Log(LOG_WARNING, "Failed to build quality string, aborting\n");
            exit(EXIT_FAILURE);
        }
        cpp_argv[cpp_argc++] = qualitystr;
    }

    if ( options.useragent != NULL ) {
        if ( asprintf(&useragentstr,
                    "--useragent=%s", options.useragent) < 0 ) {
            Log(LOG_WARNING, "Failed to build useragent string, aborting\n");
            exit(EXIT_FAILURE);
        }
        cpp_argv[cpp_argc++] = useragentstr;
    }

    if ( options.maxruntime > 0 ) {
        if ( asprintf(&runtimestr, "--runtime=%u", options.maxruntime) < 0 ) {
            Log(LOG_WARNING, "Failed to build runtime string, aborting\n");
            exit(EXIT_FAILURE);
        }
        cpp_argv[cpp_argc++] = runtimestr;
    }

    cpp_argv[cpp_argc] = NULL;

    if ( gettimeofday(&start_time, NULL) != 0 ) {
        Log(LOG_ERR, "Could not gettimeofday(), aborting test");
        exit(EXIT_FAILURE);
    }

    Log(LOG_DEBUG, "calling fork() to run test wrapper");

    /* fork and run wrapper, which will leave result in shared memory */
    if ( (pid = fork()) < 0 ) {
        perror("fork");
        return NULL;
    }

    if ( pid == 0 ) {
        /*
         * Child process runs the amp-youtube-wrapper, which can cleanly run
         * the test without worrying about clobbering shared libraries.
         * XXX We do however have to worry about the wrapper being in the path.
         */
        char *path = getenv("PATH");
        char *newpath;

        /*
         * Append the expected location of the binary to the path, rather than
         * calling exec with the full path so we can change it at runtime if
         * we need to.
         */
        if ( asprintf(&newpath, "%s:%s", path, AMP_YOUTUBE_WRAPPER_PATH) < 0 ) {
            Log(LOG_WARNING, "Failed to build path string, aborting\n");
            exit(EXIT_FAILURE);
        }

        setenv("PATH", newpath, 1);
        Log(LOG_DEBUG, "child process ok, running test wrapper");
        Log(LOG_DEBUG, "Using $PATH=%s\n", newpath);
        execvpe("amp-youtube-wrapper", cpp_argv, environ);
        Log(LOG_WARNING, "Failed to exec amp-youtube-wrapper: %s",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    Log(LOG_DEBUG, "parent process ok, waiting for wrapper to complete");

    /* parent process will just wait for the result to be ready */
    waitpid(pid, &status, 0);

    if ( !WIFEXITED(status) || WEXITSTATUS(status) == EXIT_FAILURE ) {
        Log(LOG_WARNING, "youtube test exited unexpectedly");
        return NULL;
    }

    /* the filename is /amp-testtype-pid */
    if ( asprintf(&filename, "/amp-youtube-%d", pid) < 0 ) {
        Log(LOG_WARNING, "Failed to create filename");
        return NULL;
    }

    Log(LOG_DEBUG, "reading results from shared memory: %s", filename);

    if ( (fd = shm_open(filename, O_RDONLY, 0)) < 0 ) {
        shm_unlink(filename);
        free(filename);
        Log(LOG_WARNING, "Failed to open shared file");
        return NULL;
    }

    /* in theory this won't be removed till we close the fd */
    shm_unlink(filename);
    free(filename);

    lseek(fd, 0, SEEK_SET);

    if ( read(fd, &buflen, sizeof(buflen)) != sizeof(buflen) ) {
        close(fd);
        Log(LOG_WARNING, "Failed to read length");
        return NULL;
    }

    if ( buflen > 4096 ) {
        Log(LOG_WARNING, "Ignoring too-large youtube test result");
        close(fd);
        return NULL;
    }

    buffer = calloc(1, buflen);
    if ( read(fd, buffer, buflen) != buflen ) {
        free(buffer);
        close(fd);
        Log(LOG_WARNING, "Failed to read data");
        return NULL;
    }

    close(fd);

    Log(LOG_DEBUG, "reporting results");

    youtube = amplet2__youtube__item__unpack(NULL, buflen, buffer);
    result = report_results(&start_time, youtube, &options);

    free(buffer);
    amplet2__youtube__item__free_unpacked(youtube, NULL);

    if ( urlstr ) {
        free(urlstr);
    }

    if ( qualitystr ) {
        free(qualitystr);
    }

    if ( useragentstr ) {
        free(useragentstr);
    }

    if ( runtimestr ) {
        free(runtimestr);
    }

    return result;
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

    printf("\n");
    printf("AMP YouTube test, video: %s\n", msg->header->video);
    printf("Desired quality: %s\n", get_quality_string(msg->header->quality));
    if ( msg->header->useragent ) {
        printf("User Agent: \"%s\"\n", msg->header->useragent);
    }
    if ( msg->header->maxruntime > 0 ) {
        printf("Maximum Runtime: %u seconds\n", msg->header->maxruntime);
    }

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
