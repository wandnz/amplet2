/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2019-2020 The University of Waikato, Hamilton, New Zealand.
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

/*
 * TODO account registration?
 * TODO TLS?
 * TODO build as separate package to avoid pjsip dependencies
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "sip.h"
#include "tests.h"
#include "debug.h"
#include "usage.h"
#include "../../measured/control.h"


struct option long_options[] = {
    //{"perturbate", required_argument, 0, 'p'},
    {"user-agent", required_argument, 0, 'a'},
    {"useragent", required_argument, 0, 'a'},
    {"filename", required_argument, 0, 'f'},
    {"wavfile", required_argument, 0, 'f'},
    {"time", required_argument, 0, 't'},
    {"duration", required_argument, 0, 't'},
    {"control-port", required_argument, 0, 'p'},
    {"sip-port", required_argument, 0, 'P'},
    {"disable-repeat", no_argument, 0, 'r'},
    {"server", no_argument, 0, 's'},
    {"uri", required_argument, 0, 'u'},
    {"proxy", required_argument, 0, 'y'},
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
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
void usage(void) {
    fprintf(stderr, "Usage: amp-sip -s [OPTIONS]\n");
    fprintf(stderr, "Usage: amp-sip -u uri [OPTIONS]\n");
    fprintf(stderr, "Usage: amp-sip [OPTIONS] -- destination\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Server/Client options:\n");
    fprintf(stderr, "  -a, --user-agent     <agent>   "
            "Specify User-Agent string\n");
    fprintf(stderr, "  -f, --filename       <file>    "
            "WAV audio file to play\n");
    print_interface_usage();
    fprintf(stderr, "\n");

    fprintf(stderr, "Server specific options:\n");
    fprintf(stderr, "  -P, --sip-port       <port>    "
            "Port number to listen on (def:%d)\n", SIP_SERVER_LISTEN_PORT);
    fprintf(stderr, "  -s, --server                   Run in server mode\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Client specific options:\n");
    // set by amplet2-client when starting test, used to start remote server
    /*
    fprintf(stderr, "  -p, --control-port   <port>    "
            "Control port for remote amplet2-client (def:%s)\n",
            DEFAULT_AMPLET_CONTROL_PORT);
    */
    fprintf(stderr, "  -r, --disable-repeat           "
            "Play the WAV file only once then hang up\n");
    fprintf(stderr, "  -t, --time           <seconds> "
            "Maximum duration in seconds (def:30)\n");
    fprintf(stderr, "  -u, --uri            <uri>     "
            "Run in client mode, connecting to <uri>\n");
    fprintf(stderr, "  -y, --proxy          <uri>     "
            "URI of SIP proxy to use\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Miscellaneous:\n");
    print_generic_usage();
    fprintf(stderr, "\n");
}



/*
 * Entry point for command line server/client and scheduled client.
 */
amp_test_result_t* run_sip(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    int server_flag_index = 0;

    Log(LOG_DEBUG, "Starting sip test");

    while ( (opt = getopt_long(argc, argv, "a:f:P:p:rst:u:y:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case 's': server_flag_index = optind - 1; break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: /* pass all other options through */ break;
        };
    }

    /* reset optind so the next function can parse its own arguments */
    optind = 1;

    if ( server_flag_index ) {
        /* remove the -s option before calling the server function */
        memmove(argv + server_flag_index, argv + server_flag_index + 1,
                (argc - server_flag_index - 1) * sizeof(char *));
        run_sip_server(argc-1, argv, NULL);
        return NULL;
    }

    return run_sip_client(argc, argv, count, dests);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_SIP;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("sip");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 330;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_sip;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_sip;

    /* the sip test doesn't require us to run a custom server */
    new_test->server_callback = run_sip_server;

    /* don't give the sip test a SIGINT warning, it should not take long! */
    new_test->sigint = 0;

    return new_test;
}
