/*
 * Skeleton test to demonstrate how to write a test for amplet2.
 */
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>

#include "tests.h"

int run_skeleton(int argc, char *argv[], int count, struct addrinfo **dests);
test_t *register_test(void);



static void usage(char *prog) {
    fprintf(stderr, "%s test has no required arguments.\n", prog);
    fprintf(stderr, "Any arguments it receives it will simply print.\n");
}


/*
 * Very simple main function to show how tests can be run.
 */
int run_skeleton(int argc, char *argv[], int count, struct addrinfo **dests) {
    int i;
    char address[INET6_ADDRSTRLEN];

    printf("skeleton test\n");

    /* print all the arguments that were passed in */
    printf("args:\n");
    for ( i=0; i<argc; i++) {
	printf("\targv[%d]: %s\n", i, argv[i]);
    }

    /* print all the destinations that were passed in */
    printf("dests:\n");
    for ( i=0; i<count; i++ ) {
	if ( dests[count]->ai_family == AF_INET ) {
	    inet_ntop(AF_INET,
		    &((struct sockaddr_in*)dests[count]->ai_addr)->sin_addr,
		    address, INET6_ADDRSTRLEN);
	} else if ( dests[count]->ai_family == AF_INET6 ) {
	    inet_ntop(AF_INET,
		    &((struct sockaddr_in6*)dests[count]->ai_addr)->sin6_addr,
		    address, INET6_ADDRSTRLEN);
	} else {
	    continue;
	}
	printf("\t%s\n", address);
    }

    return 0;
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_SKELETON;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("skeleton");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 30;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_skeleton;

    return new_test;
}
