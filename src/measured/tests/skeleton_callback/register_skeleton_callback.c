/*
 * Skeleton test to demonstrate how to write a test for amplet2.
 */
#include <malloc.h>
#include <string.h>
#include "schedule.h"
#include "test.h"
#include "amp_exec.h"



/*
 * Run the test with any extra arguments that were calculated by the test 
 * setup function.
 *
 * test_info_t *test contains information about the test from the schedule
 * file - options, destinations, etc
 */
void test_run_skeleton_callback(const test_schedule_item_t * const item/*, void *data*/) {
    /* extract any information from *data that this test needs */

    /* 
     * Run the test, adding any extra arguments that might have come through
     * from the data argument in the second parameter.
     */
    amp_exec_test(item, NULL);
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
    new_test->run_callback = test_run_skeleton_callback;

    /* the test binary to run, relative to the installed tests directory */
    new_test->run_binary = strdup("skeleton_callback");
    
    return new_test;
}
