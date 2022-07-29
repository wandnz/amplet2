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

#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include "config.h"
#include "testlib.h"
#include "udpstream.h"
#include "debug.h"
#include "usage.h"


struct option long_options[] = {
    {"client", required_argument, 0, 'c'},
    {"direction", required_argument, 0, 'd'},
    {"delay", required_argument, 0, 'D'},
    {"packet-count", required_argument, 0, 'n'},
    {"port", required_argument, 0, 'p'},
    {"test-port", required_argument, 0, 'P'},
    {"rtt-samples", required_argument, 0, 'r'},
    {"server", no_argument, 0, 's'},
    {"size", required_argument, 0, 'z'},
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
//XXX perturbate vs port


/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
void usage(void) {
    fprintf(stderr, "Usage: amp-udpstream -s [OPTIONS]\n");
    fprintf(stderr, "       amp-udpstream -c host [OPTIONS]\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Server/Client options:\n");
    fprintf(stderr, "  -p, --port           <port>    "
            "Port number to use (default %d)\n", DEFAULT_CONTROL_PORT);
    print_interface_usage();
    fprintf(stderr, "\n");

    fprintf(stderr, "Server specific options:\n");
    fprintf(stderr, "  -s, --server                   Run in server mode\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Client specific options:\n");
    fprintf(stderr, "  -c, --client         <host>    "
            "Run in client mode, connecting to <host>\n");
    fprintf(stderr, "  -d, --direction      <dir>     "
            "TODO magic value describing direction\n");
    fprintf(stderr, "  -D, --delay          <usec>    "
            "Interval between packets (default %dus)\n",
            DEFAULT_UDPSTREAM_INTER_PACKET_DELAY);
    fprintf(stderr, "  -n, --packet-count   <count>   "
            "Number of packets to send (default %d)\n",
            DEFAULT_UDPSTREAM_PACKET_COUNT);
    fprintf(stderr, "  -P, --test-port      <port>    "
            "Port number to test on (default %d)\n", DEFAULT_TEST_PORT);
    fprintf(stderr, "  -r, --rtt-samples    <N>       "
            "Sample every Nth probe for RTT (default %d)\n",
            DEFAULT_UDPSTREAM_RTT_SAMPLES);
    fprintf(stderr, "  -z, --packet-size    <bytes>   "
            "Size of datagrams to send (default %d)\n",
            DEFAULT_UDPSTREAM_PACKET_LENGTH);
    fprintf(stderr, "\n");

    fprintf(stderr, "Miscellaneous:\n");
    print_generic_usage();
    fprintf(stderr, "\n");
}



/*
 * TODO const up the dest arguments so cant be changed?
 */
amp_test_result_t* run_udpstream(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    int server_flag_index = 0;

    Log(LOG_DEBUG, "Starting udpstream test");

    while ( (opt = getopt_long(argc, argv, "cd:D:n:p:P:r:sz:I:Q:Z:4::6::hvx",
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
        run_udpstream_server(argc-1, argv, NULL);
        return NULL;
    }

    return run_udpstream_client(argc, argv, count, dests);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_UDPSTREAM;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("udpstream");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_udpstream;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_udpstream;

    /* the udpstream test doesn't require us to run a custom server */
    new_test->server_callback = run_udpstream_server;

    /* don't give the test a SIGINT warning, it should not take long! */
    new_test->sigint = 0;

    /* resolve targets before passing them to the test */
    new_test->do_resolve = 1;

    return new_test;
}
