#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "schedule.h"
#include "test.h"



/*
 * Combine the test parameters with any from the test set up function and
 * apply them to the proper test binary as provided by the test registration.
 * Run the test with execv() and let it do its thing.
 */
void amp_exec_test(const test_schedule_item_t * const item, char **user_args) {
    char full_path[MAX_PATH_LENGTH];
    /* XXX TODO check we stay under this limit */
    /* TODO destinations will need to be added too, bump this size?
     * TODO actual limit is a number of bytes I think, should I count them?
     */
    char *argv[MAX_TEST_ARGS]; 
    int argc = 0;
    int offset;
    test_t *test;
    
    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);
    
    test = amp_tests[item->test_id];

    strcpy(full_path, AMP_TEST_DIRECTORY);
    strcat(full_path, test->run_binary);

    /* start building parameter array */
    argv[argc++] = test->run_binary;

    /* add in any of the test parameters from the schedule file */
    if ( item->params != NULL ) {
	for ( offset=0; item->params[offset] != NULL; offset++ ) {
	    argv[argc++] = item->params[offset];
	}
    }

    /* add in any of the test parameters from the custom test setup */
    if ( user_args != NULL ) {
	for ( offset=0; user_args[offset] != NULL; offset++ ) {
	    argv[argc++] = user_args[offset];
	}
    }

    /* null terminate the list before we give it to execv() */
    argv[argc] = NULL;

    printf("Running test: %s (%s)\n", test->name, full_path);
    for ( offset = 0; offset<argc; offset++ ) {
	printf("arg%d: %s\n", offset, argv[offset]);
    }
    
    execv(full_path, argv);

    /* should not get to this point */
    perror("execv");
    exit(1);
}
