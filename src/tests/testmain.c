#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <dlfcn.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "tests.h"
#include "modules.h"
#include "testmain.h"



/* FIXME? this is pretty much a copy and paste of code in test.c */
static test_t *get_test_info() {
    void *hdl;
    test_t *test_info;
    const char *error = NULL;

    hdl = dlopen(NULL, RTLD_LAZY);

    if ( !hdl ) {
	fprintf(stderr, "Failed to dlopen() self\n");
	exit(1);
    }

    test_reg_ptr r_func = (test_reg_ptr)dlsym(hdl, "register_test");
    if ( (error = dlerror()) != NULL ) {
	/* it doesn't have this function, it's not one of ours, ignore */
	fprintf(stderr, "Failed to find register_test function: %s\n", error);
	dlclose(hdl);
	exit(1);
    }

    /* use the register_test function to determine what main function to run */
    test_info = r_func();

    if ( test_info == NULL ) {
	fprintf(stderr, "Got NULL response from register_test function\n");
	dlclose(hdl);
	exit(1);
    }

    test_info->dlhandle = hdl;
    test_info->report = 0;

    return test_info;
}



/*
 * Generic main function to allow all tests to be run as both normal binaries
 * and AMP libraries. This function will deal with converting command line
 * arguments into test arguments and a list of destinations (such as AMP
 * provides when it runs the tests).
 *
 * Arguments to the test should be provided as normal, and any destinations
 * included on the end after a -- seperator. For example:
 *
 * ./foo -a 1 -b 2 -c -- 10.0.0.1 10.0.0.2 10.0.0.3
 */
int main(int argc, char *argv[]) {
    test_t *test_info;
    struct addrinfo **dests;
    struct addrinfo hint;
    struct addrinfo *result, *rp;
    int count;
    int opt;
    int i;

    /* load information about the test, including the callback functions */
    test_info = get_test_info();
    /* 
     * FIXME is this the best way to get this looking like it does when
     * run through measured? Just filling in the one value that we know we
     * will be looking at later when reporting.
     */
    amp_tests[test_info->id] = test_info;

    /* suppress "invalid argument" errors from getopt */
    opterr = 0;

    /* 
     * deal with command line arguments - split them into actual arguments
     * and destinations in the style the AMP tests want. Using "-" as the 
     * optstring means that non-option arguments are treated as having an
     * option with character code 1 (which prevents them from being shuffled
     * to the end of the list). All test arguments will be preserved, and the
     * destinations listed after the -- marker can be removed easily.
     */
    while ( (opt = getopt(argc, argv, "-")) != -1 ) {
	/* do nothing, just use up arguments until we reach the -- marker */
    }

    dests = NULL;
    count = 0;

    /* accept pretty much anything and take whatever we get back */
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_flags = 0;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = 0;
    hint.ai_addrlen = 0;
    hint.ai_addr = NULL;
    hint.ai_canonname = NULL;
    hint.ai_next = NULL;

    /* process all destinations */
    /* TODO prevent duplicate destinations? */
    for ( i=optind; i<argc; i++ ) {
	/* check if adding the new destination would be allowed by the test */
	if ( test_info->max_targets > 0 && count >= test_info->max_targets ) {
	    /* ignore any extra destinations but continue with the test */
	    printf("Exceeded max of %d destinations, skipping remainder\n", 
		    test_info->max_targets);
	    break;
	}

	if ( getaddrinfo(argv[i], NULL, &hint, &result) != 0 ) {
	    perror("getaddrinfo");
	    continue;
	}
	
	/* 
	 * If this is a new destination, link it to the last element so that
	 * we can clean them all up with a single freeaddrinfo() call.
	 */
	if ( count > 0 && result != NULL ) {
	    dests[count-1]->ai_next = result;
	}

	/* add all the results of getaddrinfo() to the list of destinations */
	for ( rp=result; rp != NULL; rp=rp->ai_next ) {
	    /* use the given name rather than the canonical name */
	    rp->ai_canonname = strdup(argv[i]);
	    /* make room for a new destination and fill it */
	    dests = realloc(dests, (count + 1) * sizeof(struct addrinfo));
	    dests[count] = rp;
	    count++;
	}
    }

    /* prematurely terminate argv so the test doesn't see the destinations */
    argv[optind] = NULL;

    /* reset optind so the test can call getopt normally on it's arguments */
    optind = 1;

    /* make sure the RNG is seeded so the tests don't have to worry */
    srandom(time(NULL));

    /* pass arguments and destinations through to the main test run function */
    test_info->run_callback(argc, argv, count, dests);

    /* tidy up after ourselves */
    freeaddrinfo(*dests);
    free(dests);
    dlclose(test_info->dlhandle);
    free(test_info->name);
    free(test_info);

    return 0;
}
