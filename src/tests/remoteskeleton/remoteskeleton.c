/*
 * Skeleton test to demonstrate how to write a test for amplet2.
 */
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <openssl/ssl.h>

#include "tests.h"
#include "debug.h"
#include "testlib.h"
#include "global.h"

int run_remoteskeleton(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_remoteskeleton(void *data, uint32_t len);
void server_remoteskeleton(int argc, char *argv[], SSL *ssl);
test_t *register_test(void);



static void usage(char *prog) {
    fprintf(stderr, "%s test has no required arguments.\n", prog);
    fprintf(stderr, "Any arguments it receives it will simply print.\n");
}


/*
 * Very simple main function to show how tests can be run.
 */
int run_remoteskeleton(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int i;
    char address[INET6_ADDRSTRLEN];
    struct timeval start_time;
    uint32_t result;
    int opt;
    uint16_t remote;

    printf("remote skeleton test\n");

    /* use getopt to check for -h first, then fall through to dump all args */
    while ( (opt = getopt(argc, argv, "h")) != -1 ) {
	switch ( opt ) {
	    case 'h': usage(argv[0]); exit(0);
            default: /* pass through */ break;
	};
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(-1);
    }

    /* print all the arguments that were passed in */
    printf("args:\n");
    for ( i=0; i<argc; i++) {
	printf("\targv[%d]: %s\n", i, argv[i]);
    }

    /* print all the destinations that were passed in */
    printf("dests: %d\n", count);
    result = count;
    for ( i=0; i<count; i++ ) {
	if ( dests[i]->ai_family == AF_INET ) {
	    inet_ntop(AF_INET,
		    &((struct sockaddr_in*)dests[i]->ai_addr)->sin_addr,
		    address, INET6_ADDRSTRLEN);
	} else if ( dests[i]->ai_family == AF_INET6 ) {
	    inet_ntop(AF_INET,
		    &((struct sockaddr_in6*)dests[i]->ai_addr)->sin6_addr,
		    address, INET6_ADDRSTRLEN);
	} else {
            result--;
	    continue;
	}
	printf("\t%s\n", address);
    }

    if ( (remote = start_remote_server(AMP_TEST_REMOTE_SKELETON,
                    dests[0])) == 0 ) {
        Log(LOG_WARNING, "Failed to start remote server, aborting test");
        return -1;
    }

    Log(LOG_DEBUG, "Got port %d from remote server", remote);


    /* report some sort of dummy result */
    report(AMP_TEST_REMOTE_SKELETON, start_time.tv_sec, (void*)&result,
            sizeof(uint32_t));

    return 0;
}



/*
 * Print results of the skeleton test.
 */
void print_remoteskeleton(void *data, uint32_t len) {
    /* TODO check version number for any result structures */
    assert(data);
    assert(len == sizeof(uint32_t));

    printf("Result: got %d address(es) of known family (IPv4/IPv6)\n",
            *(uint32_t*)data);
}


void server_remoteskeleton(int argc, char *argv[], SSL *ssl) {
    printf("SKELETON SERVER\n");
    if ( send_server_port(ssl, 6699) < 0 ) {
        printf("failed to send server port\n");
    } else {
        printf("sent server port ok\n");
    }
}


/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_REMOTE_SKELETON;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("remoteskeleton");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 30;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_remoteskeleton;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_remoteskeleton;

    /* function to run on the remote end to assist with the test */
    new_test->server_callback = server_remoteskeleton;

    return new_test;
}
