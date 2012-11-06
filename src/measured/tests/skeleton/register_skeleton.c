/*
 * Skeleton test to demonstrate how to write a test for amplet2.
 */
#include <malloc.h>
#include <string.h>
#include "test.h"


#if 0
/* 
 * This is where you would do any pre-test setup. For example, you could
 * use this space to:
 * - start remote programs required
 * - negotiate port numbers to be used
 *
 * The return value from this function will later be passed into the main 
 * function of the test itself.
 */
void *test_setup_skeleton() {

    /* return any information that will be useful to the test */
    return NULL;
}
#endif


/*
 * Run the test with any extra arguments that were calculated by the test 
 * setup function.
 *
 * test_info_t *test contains information about the test from the schedule
 * file - options, destinations, etc
 */
#if 0
void test_run_skeleton(/* test_info_t *test,*/ void *data) {
    /* extract any information from *data that this test needs */

    /* 
     * Run the test, adding any extra arguments that might have come through
     * from the data argument in the second parameter.
     */
    //amp_exec_test(/*test,*/ NULL);
}
#endif



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
    new_test->run_callback = NULL;

    /* the test binary to run, relative to the installed tests directory */
    new_test->run_binary = strdup("skeleton");
    
    //new_test->setup_callback = test_setup_skeleton;
    //new_test->run_callback = test_run_skeleton;

    return new_test;
}
