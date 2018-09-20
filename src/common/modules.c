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

#include <stdlib.h>
#include <glob.h>
#include <dlfcn.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "debug.h"
#include "modules.h"


test_t *register_one_test(char *filename) {
    void *hdl;
    test_t *test_info;
    const char *error = NULL;

    hdl = dlopen(filename, RTLD_LAZY);

    if ( !hdl ) {
	Log(LOG_WARNING, "Failed to dlopen() file %s", filename);
	return NULL;
    }

    test_reg_ptr r_func = (test_reg_ptr)dlsym(hdl, "register_test");
    if ( (error = dlerror()) != NULL ) {
        /* it doesn't have this function, it's not one of ours, ignore */
        Log(LOG_WARNING, "Failed to find register_test function in %s",
                filename);
        dlclose(hdl);
        return NULL;
    }

    /* use the register_test function to determine what main function to run */
    test_info = r_func();

    if ( test_info == NULL ) {
        Log(LOG_WARNING,
                "Got NULL response from register_test function in %s",
                filename);
        dlclose(hdl);
        return NULL;
    }

    test_info->dlhandle = hdl;

    assert(test_info->name);
    assert(test_info->run_callback);
    assert(test_info->print_callback);

    return test_info;
}


/*
 * Register all the tests in the given directory as being available.
 */
int register_tests(char *location) {
    glob_t glob_buf;
    test_t *new_test;
    char full_loc[MAX_PATH_LENGTH];
    uint32_t i;
    int count = 0;

    if ( location == NULL ) {
	Log(LOG_ALERT, "Test directory not given.");
	return -1;
    }

    if ( strlen(location) >= MAX_PATH_LENGTH - 6 ) {
	Log(LOG_ALERT, "Test directory path too long.");
	return -1;
    }

    amp_tests = calloc(1, sizeof(test_t*));

    /* find all the .so files that exist in the directory */
    strcpy(full_loc, location);
    strcat(full_loc, "/*.so");
    glob(full_loc, 0, NULL, &glob_buf);

    Log(LOG_INFO, "Loading test modules from %s (found %zd candidates)",
	    location, glob_buf.gl_pathc);

    for ( i=0; i<glob_buf.gl_pathc; i++ ) {
        new_test = register_one_test(glob_buf.gl_pathv[i]);
        if ( new_test == NULL ) {
            continue;
        }
        /* TODO walk the list and warn of collisions with names or ids? */
	/* add the test to the list of all available tests */
        amp_tests[count++] = new_test;
        amp_tests = realloc(amp_tests, sizeof(test_t*) * (count + 1));
        if ( amp_tests == NULL ) {
            Log(LOG_WARNING, "Error allocating memory for new test, aborting");
            exit(EXIT_FAILURE);
        }
        amp_tests[count] = NULL;
	Log(LOG_DEBUG, "Loaded test %s", new_test->name);
    }

    globfree(&glob_buf);

    return 0;
}



/*
 * Close all the dlhandles pointing to test objects.
 */
void unregister_tests() {
    test_t **test;

    Log(LOG_DEBUG, "Unregistering all tests");

    if ( amp_tests == NULL ) {
        return;
    }

    for ( test = amp_tests; *test != NULL; test++ ) {
        free((*test)->name);
        dlclose((*test)->dlhandle);
        free(*test);
    }

    free(amp_tests);
}



/*
 * Lookup a test definition by the test id.
 */
test_t *get_test_by_id(uint64_t id) {
    test_t **test;

    if ( amp_tests == NULL ) {
        return NULL;
    }

    for ( test = amp_tests; *test != NULL; test++ ) {
        if ( (*test)->id == id ) {
            return *test;
        }
    }

    return NULL;
}



/*
 * Lookup a test definition by the test name.
 */
test_t *get_test_by_name(char *name) {
    test_t **test;

    if ( amp_tests == NULL ) {
        return NULL;
    }

    for ( test = amp_tests; *test != NULL; test++ ) {
        if ( strcmp((*test)->name, name) == 0 ) {
            return *test;
        }
    }

    return NULL;
}
