/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2019 The University of Waikato, Hamilton, New Zealand.
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

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "external.h"
#include "external.pb-c.h"
#include "debug.h"
#include "usage.h"


static struct option long_options[] = {
    {"perturbate", required_argument, 0, 'p'},
    {"command", required_argument, 0, 'c'},
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
 * Construct a protocol buffer message containing all the test options and the
 * results for each destination address.
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        char *target, char *command, int64_t *value) {

    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Log(LOG_DEBUG, "Building external report, command:%s\n", command);

    Amplet2__External__Report msg = AMPLET2__EXTERNAL__REPORT__INIT;
    Amplet2__External__Header header = AMPLET2__EXTERNAL__HEADER__INIT;
    Amplet2__External__Item *item =
            (Amplet2__External__Item*)malloc(sizeof(Amplet2__External__Item));

    /* populate the header with all the test options */
    header.command = command;

    /* populate the single test result */
    amplet2__external__item__init(item);
    if ( value ) {
        item->has_value = 1;
        item->value = *value;
    }

    item->name = target;

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = &item;
    msg.n_reports = 1;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__external__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__external__report__pack(&msg, result->data);

    free(item);

    return result;
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-external [-hrvx] [-p perturbate] -c command"
            " [-- destination]"
            "\n\n");

    /* test specific options */
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --perturbate     <msec>    "
            "Maximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -c, --command        <command> "
            "Path to the program that should be run\n");

    //print_probe_usage();
    //print_interface_usage();
    print_generic_usage();
}



/*
 *
 */
static int is_valid_command(char *command) {
    regex_t regex;

    /* force commands to use only letters and numbers */
    if ( regcomp(&regex, "^[a-zA-Z0-9]+$", REG_EXTENDED) < 0 ) {
        return 0;
    }

    if ( regexec(&regex, command, 0, NULL, 0) != 0 ) {
        regfree(&regex);
        return 0;
    }

    regfree(&regex);
    return 1;
}



/*
 * Main function to run the external test, returning a result structure that
 * will later be printed or sent across the network.
 */
amp_test_result_t* run_external(int argc, char *argv[], int count,
        struct addrinfo **dests) {

    int opt;
    struct timeval start_time;
    amp_test_result_t *result;
    char *usrcmd = NULL, *fullcmd = NULL;
    int perturbate = 0;
    FILE *output;
    int64_t *value = NULL;
    int64_t value_storage;
    char *target = NULL;

    Log(LOG_DEBUG, "Starting EXTERNAL test");

    /*
     * TODO any extra information to add about the test? Are big numbers
     * better or worse (e.g. latency vs throughput)
     */

    while ( (opt = getopt_long(argc, argv, "p:c:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4': /* currently does nothing for this test */ break;
            case '6': /* currently does nothing for this test */ break;
            case 'I': /* currently does nothing for this test */ break;
            case 'Q': /* currently does nothing for this test */ break;
            case 'Z': /* currently does nothing for this test */ break;
            case 'p': perturbate = atoi(optarg); break;
            case 'c': usrcmd = optarg; break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
	};
    }

    /*
     * TODO is it appropriate to take a destination? Do we want to pass on
     * the name or the address to the program? What about other arguments?
     */
    if ( dests && count > 0 ) {
        assert(dests[0]);
        assert(dests[0]->ai_canonname);

        target = dests[0]->ai_canonname;
        if ( count > 1 ) {
            Log(LOG_WARNING, "Too many targets, ignoring all but the first");
        }
    }

    if ( !usrcmd ) {
        Log(LOG_WARNING, "Missing external test command!\n");
        usage();
        exit(EXIT_FAILURE);
    }

    /* sanity check user command */
    if ( !is_valid_command(usrcmd) ) {
        Log(LOG_WARNING, "Invalid characters in command");
        exit(EXIT_FAILURE);
    }

    /* delay the start by a random amount if perturbate is set */
    if ( perturbate ) {
	int delay;
	delay = perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate %dms, waiting %dus", perturbate, delay);
	usleep(delay);
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(EXIT_FAILURE);
    }

    /* build the final command string with correct path and destinations */
    if ( asprintf(&fullcmd, "%s/%s %s", AMP_EXTERNAL_BIN_DIRECTORY, usrcmd,
                target ? target : "") < 0 ) {
	Log(LOG_ERR, "Could not build command string, aborting test");
	exit(EXIT_FAILURE);
    }

    /* run command */
    if ( (output = popen(fullcmd, "r")) != NULL ) {
        int status;

        /* wait for command to finish to see if we might have useful output */
        waitpid(-1, &status, 0);

        if ( WIFEXITED(status) && WEXITSTATUS(status) == 0 ) {
            /* try to read a single integer, anything else is an error */
            if ( fscanf(output, "%" SCNd64, &value_storage) == 1 ) {
                value = &value_storage;
            } else {
                Log(LOG_WARNING, "Failed to parse command output");
            }
        } else {
            Log(LOG_WARNING, "Command exit status: %d", WEXITSTATUS(status));
        }

        pclose(output);
    } else {
        Log(LOG_WARNING, "Failed to run command: %s", strerror(errno));
    }

    // XXX should failure to run command report no value, or not report?

    /* send report */
    result = report_results(&start_time, target, usrcmd, value);

    free(fullcmd);

    return result;
}



/*
 * Print test results to stdout, nicely formatted for the standalone test
 */
void print_external(amp_test_result_t *result) {
    Amplet2__External__Report *msg;
    Amplet2__External__Item *item;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__external__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print test header information */
    printf("\nAMP external test, command: %s\n", msg->header->command);

    /* print each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];

        if ( item->name ) {
            printf("%s: ", item->name);
        }

        if ( item->has_value ) {
            printf("%" PRId64, item->value);
        } else {
            printf("no result");
        }
        printf("\n");
    }
    printf("\n");

    amplet2__external__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_EXTERNAL;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("external");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_external;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_external;

    /* the external test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the external test a SIGINT warning */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        char *target, char *command, int64_t *value) {
    return report_results(start_time, target, command, value);
}
#endif
