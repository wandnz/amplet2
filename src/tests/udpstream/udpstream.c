#include <stdio.h>
#include <getopt.h>
#include <malloc.h>
#include <string.h>

#include "config.h"
#include "udpstream.h"


struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"interface", required_argument, 0, 'I'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {"perturbate", required_argument, 0, 'p'},
    {"size", required_argument, 0, 's'},
    {"client", required_argument, 0, 'c'},
    {"version", no_argument, 0, 'v'},
    {"ipv4", required_argument, 0, '4'},
    {"ipv6", required_argument, 0, '6'},
    {NULL, 0, 0, 0}
};



/*
 *
 */
void usage(char *prog) {
    printf("TODO usage, based on throughput\n");
    fprintf(stderr, "%s\n", prog);
}



/*
 *
 */
void version(char *prog) {
    fprintf(stderr, "%s\n", prog);
    fprintf(stderr, "%s, amplet version %s, protocol version %d\n", prog,
            PACKAGE_STRING, AMP_UDPSTREAM_TEST_VERSION);
}



/*
 * Reimplementation of the udpstream test from AMP
 *
 * TODO const up the dest arguments so cant be changed?
 */
int run_udpstream(int argc, char *argv[], int count, struct addrinfo **dests) {
    int opt;
    int option_index = 0;
    int server_flag_index = 0;

    Log(LOG_DEBUG, "Starting udpstream test");

    /* XXX this option string needs to be up to date with server and client? */
    while ( (opt = getopt_long(argc, argv,"?hvp:P:rsz:o:i:Nm:n:wS:c:d:4:6:I:t:Z:",
                    long_options, &option_index)) != -1 ) {
        switch ( opt ) {
            case 's': server_flag_index = optind - 1; break;
            case 'v': version(argv[0]); exit(0);
            case '?':
            case 'h': usage(argv[0]); exit(0);
            default: break;
        };
    }

    /* reset optind so the next function can parse its own arguments */
    optind = 1;

    if ( server_flag_index ) {
        /* remove the -s option before calling the server function */
        memmove(argv + server_flag_index, argv + server_flag_index + 1,
                (argc - server_flag_index - 1) * sizeof(char *));
        run_udpstream_server(argc-1, argv, NULL);
    } else {
        run_udpstream_client(argc, argv, count, dests);
    }

    return 0;
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
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

    return new_test;
}
