/*
 * Skeleton test to demonstrate how to write a test for amplet2.
 * TODO: this test and the other skeleton are now very similar, can we make
 * this one more complex to show off more stuff, like starting remote servers?
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "schedule.h"
#include "test.h"

test_t *register_test(void);
int run_skeleton_callback(int argc, char *argv[], int count, 
	struct addrinfo **dests);


/*
 * Very simple program to show how tests can be run.
 */
int run_skeleton_callback(int argc, char *argv[], int count, 
	struct addrinfo **dests) {

    int i;

    printf("skeleton callback test\n");
    printf("argc: %d\n", argc);

    for ( i=0; i<argc; i++)  {
	printf("argv[%d]: %s\n", i, argv[i]);
    }

    return 0;
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_SKELETON_CALLBACK;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("skeleton callback");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 3;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 30;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_skeleton_callback;
    
    return new_test;
}
