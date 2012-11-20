#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "schedule.h"
#include "test.h"
#include "nametable.h"
#include "debug.h"



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
    uint32_t argc = 0;
    uint32_t offset;
    test_t *test;
    
    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);
    assert(item->dest_count > 0);
    
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


    Log(LOG_DEBUG, "Running test: %s (%s) to %d destinations:\n", test->name, 
	    full_path, item->dest_count);

    for ( offset=0; offset < item->dest_count; offset++ ) {
	Log(LOG_DEBUG, "dest%d: %s\n", offset, 
		address_to_name(item->dests[offset]));
    }
    
    for ( offset = 0; offset<argc; offset++ ) {
	Log(LOG_DEBUG, "arg%d: %s\n", offset, argv[offset]);
    }
    
    execv(full_path, argv);

    /* should not get to this point */
    perror("execv");
    exit(1);
}
