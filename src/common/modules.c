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



/*
 * Register all the tests in the given directory as being available.
 */
int register_tests(char *location) {
    glob_t glob_buf;
    void *hdl;
    test_t *new_test;
    const char *error = NULL;
    char full_loc[MAX_PATH_LENGTH];
    uint32_t i;

    if ( location == NULL ) {
	Log(LOG_ALERT, "Test directory not given.");
	return -1;
    }

    if ( strlen(location) >= MAX_PATH_LENGTH - 6 ) {
	Log(LOG_ALERT, "Test directory path too long.");
	return -1;
    }

    /* initialise all possible tests to NULL */
    for ( i=0; i<AMP_TEST_LAST; i++ ) {
	amp_tests[i] = NULL;
    }

    /* find all the .so files that exist in the directory */
    strcpy(full_loc, location);
    strcat(full_loc, "/*.so");
    glob(full_loc, 0, NULL, &glob_buf);

    Log(LOG_INFO, "Loading test modules from %s (found %zd candidates)",
	    location, glob_buf.gl_pathc);

    for ( i=0; i<glob_buf.gl_pathc; i++ ) {
        hdl = dlopen(glob_buf.gl_pathv[i], RTLD_LAZY);

	if ( !hdl ) {
	    Log(LOG_WARNING, "Failed to dlopen() file %s",
		    glob_buf.gl_pathv[i]);
	    continue;
	}

	test_reg_ptr r_func = (test_reg_ptr)dlsym(hdl, "register_test");
	if ( (error = dlerror()) != NULL ) {
	    /* it doesn't have this function, it's not one of ours, ignore */
	    Log(LOG_WARNING, "Failed to find register_test function in %s",
		    glob_buf.gl_pathv[i]);
	    dlclose(hdl);
	    continue;
	}

	new_test = r_func();

	if ( new_test == NULL ) {
	    Log(LOG_WARNING,
		    "Got NULL response from register_test function in %s",
		    glob_buf.gl_pathv[i]);
	    dlclose(hdl);
	    continue;
	}

	new_test->dlhandle = hdl;

	assert(new_test->name);
	assert(new_test->run_callback);
	assert(new_test->print_callback);

	/* add the test to the list of all available tests */
	amp_tests[new_test->id] = new_test;
	Log(LOG_DEBUG, "Loaded test %s (id=%d)", new_test->name, new_test->id);
    }

    globfree(&glob_buf);

    return 0;
}



/*
 * Close all the dlhandles pointing to test objects.
 */
void unregister_tests() {
    int i = 0;

    Log(LOG_DEBUG, "Unregistering all tests");

    for ( i=0; i<AMP_TEST_LAST; i++) {
	if ( amp_tests[i] != NULL ) {
	    dlclose(amp_tests[i]->dlhandle);
	}
    }
}



/*
 * Given a test name, return the test id.
 */
test_type_t get_test_id(const char *testname) {
    int i;

    for ( i=0; i<AMP_TEST_LAST; i++ ) {
	if ( amp_tests[i] != NULL ) {
	    if ( strcmp(amp_tests[i]->name, testname) == 0 ) {
		return i;
	    }
	}
    }
    return AMP_TEST_INVALID;
}

