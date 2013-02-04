#include <stdlib.h>
#include <glob.h>
#include <dlfcn.h>
#include <string.h>
#include <assert.h>

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
	new_test->report = 1;

	assert(new_test->name);
	assert(new_test->run_callback);
	assert(new_test->save_callback);
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
	    free(amp_tests[i]->name);
	    free(amp_tests[i]);
	}
    }
}
