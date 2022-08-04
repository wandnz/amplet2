/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Authors: Richard Sanger
 *          Brendon Jones
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

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "throughput.h"
#include "debug.h"
#include "usage.h"


struct option long_options[] =
    {
        {"client", required_argument, 0, 'c'},
        {"direction", required_argument, 0, 'd'},
        {"rcvbuf", required_argument, 0, 'i'},
        {"mss", required_argument, 0, 'M'},
        {"nodelay", no_argument, 0, 'N'},
        {"sndbuf", required_argument, 0, 'o'},
        {"port", required_argument, 0, 'p'},
        {"test-port", required_argument, 0, 'P'},
        {"randomise", no_argument, 0, 'r'},
        {"server", no_argument, 0, 's'},
        {"schedule", required_argument, 0, 'S'},
        {"time", required_argument, 0, 't'},
        {"protocol", required_argument, 0, 'u'},
        {"write-size", required_argument, 0, 'z'},
        {"dscp", required_argument, 0, 'Q'},
        {"interpacketgap", required_argument, 0, 'Z'},
        {"interface", required_argument, 0, 'I'},
        {"ipv4", optional_argument, 0, '4'},
        {"ipv6", optional_argument, 0, '6'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'x'},
        {NULL,0,0,0}
    };

/*
 * This usage statement is based on iperf, we do pretty similar things.
 */
void usage(void) {
    fprintf(stderr, "Usage: amp-throughput -s [OPTIONS]\n");
    fprintf(stderr, "       amp-throughput -c host [OPTIONS]\n");
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
    fprintf(stderr, "  -i, --rcvbuf         <bytes>   "
            "Maximum size of the receive (input) buffer\n");
    fprintf(stderr, "  -M, --mss            <bytes>   "
            "Set TCP maximum segment size\n");
    fprintf(stderr, "  -N, --nodelay                  "
            "Disable Nagle's Algorithm (set TCP_NODELAY)\n");
    fprintf(stderr, "  -o, --sndbuf         <bytes>   "
            "Maximum size of the send (output) buffer\n");
    fprintf(stderr, "  -P, --test-port      <port>    "
            "Port number to test on (default %d)\n", DEFAULT_TEST_PORT);
    fprintf(stderr, "  -r, --randomise                "
            "Randomise data in every packet sent\n");
    fprintf(stderr, "  -S, --schedule       <seq>     "
            "Test schedule (see below)\n");
    fprintf(stderr, "  -t, --time           <sec>     "
            "Time in seconds to transmit (default 10s)\n");
    fprintf(stderr, "  -u, --protocol       <proto>   "
            "Protocol to imitate (default:none, options: none, http)\n");
    fprintf(stderr, "  -z, --write-size     <bytes>   "
            "Length of buffer to write (default %d)\n",
            (int)DEFAULT_WRITE_SIZE );
    fprintf(stderr, "\n");

    fprintf(stderr, "Miscellaneous:\n");
    print_generic_usage();
    fprintf(stderr, "\n");

    fprintf(stderr, "Socket options such as rcvbuf, sndbuf, mss and nodelay "
            "will be set on both\nthe client and the server.");
    fprintf(stderr, "\n\n");

    /* TODO make schedules like iperf? just do one way for a period */
    fprintf(stderr, "A schedule is a sequence of tests. Each test starts with single character\n");
    fprintf(stderr, "representing its type. Tests are separated by a single comma ','.\n");
    fprintf(stderr, "Valid types are:\n");
    fprintf(stderr, "  s<num_bytes> run a server -> client test, sending a fixed number of bytes\n");
    fprintf(stderr, "  S<num_bytes> run a client -> server test, sending a fixed number of bytes\n");
    fprintf(stderr, "  t<ms>        run a server -> client test, for the time given in milliseconds\n");
    fprintf(stderr, "  T<ms>        run a client -> server test, for the time given in milliseconds\n");
    fprintf(stderr, " e.g. -S \"t1000,T1000\"    Run two tests each for 1 second first S2C then C2S\n");
    fprintf(stderr, " e.g. -S \"s10000,S10000\"  Run two tests S2C then C2S each sending 10,000 bytes\n");
}



/*
 * Combined entry point for throughput tests that will run the appropriate
 * part of the test - server or client.
 */
amp_test_result_t* run_throughput(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    int server_flag_index = 0;

    Log(LOG_DEBUG, "Starting throughput test");

    /* this option string needs to be kept up to date with server and client */
    while ( (opt = getopt_long(argc, argv,
                    "c:d:i:Nm:o:p:P:rsS:t:u:z:I:Q:Z:4::6::hvx",
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
        run_throughput_server(argc-1, argv, NULL);
        return NULL;
    }

    return run_throughput_client(argc, argv, count, dests);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_THROUGHPUT;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("throughput");

    /* how many targets a single instance of this test can have  - Only 1 */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_throughput;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_throughput;

    /* function to call to start the throughput server */
    new_test->server_callback = run_throughput_server;

    /* don't give the throughput test a SIGINT warning */
    new_test->sigint = 0;

    /* resolve targets before passing them to the test */
    new_test->do_resolve = 1;

    return new_test;
}
