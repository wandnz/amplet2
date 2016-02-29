#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <dlfcn.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "debug.h"
#include "tests.h"
#include "modules.h"
#include "ssl.h"
#include "global.h" /* just for temporary ssl testing stuff */
#include "messaging.h" /* just for temporary ssl testing stuff */
#include "ampresolv.h"
#include "testlib.h"
#include "../measured/control.h" /* just for CONTROL_PORT */


struct option long_options[] = {
    {"cacert", required_argument, 0, '0'},
    {"cert", required_argument, 0, '9'},
    {"key", required_argument, 0, '8'},
    {"debug", no_argument, 0, 'x'},
    {"help", no_argument, 0, 'h'},
};



/* FIXME? this is pretty much a copy and paste of code in test.c */
static test_t *get_test_info(void) {
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
    struct addrinfo *addrlist = NULL, *rp;
    int count;
    int opt;
    int option_index = 0;
    int i;
    char *nameserver = NULL;
    int remaining = 0;
    pthread_mutex_t addrlist_lock;
    char *sourcev4 = NULL;
    char *sourcev6 = NULL;
    amp_test_result_t *result;
    int test_argc;
    char **test_argv;


    /* load information about the test, including the callback functions */
    test_info = get_test_info();

    /* fill in just our test info, we don't need all the others */
    amp_tests[test_info->id] = test_info;

    /* suppress "invalid argument" errors from getopt */
    opterr = 0;

    /* start building new argv for the test, which will be a subset of argv */
    test_argc = 1;
    test_argv = calloc(2, sizeof(char*));
    test_argv[0] = argv[0];

    /*
     * deal with command line arguments - split them into actual arguments
     * and destinations in the style the AMP tests want. Using "-" as the
     * optstring means that non-option arguments are treated as having an
     * option with character code 1, which makes different style arguments
     * (both styles of long arguments, and short ones) appear consistently.
     * We could have not used it so that unknown arguments are shuffled to
     * the end of the list and then taken just the argv array after the last
     * known argument, but for some reason the permutation isn't working?
     */
    while ( (opt = getopt_long(argc, argv, "-x0:9:8:D:4:6:",
                    long_options, &option_index)) != -1 ) {
	/* generally do nothing, just use up arguments until the -- marker */
        switch ( opt ) {
            /* -x is an option only we care about for now - enable debug */
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            /* nameserver config is also only for us and not passed on */
            case 'D': nameserver = optarg;
                      break;
            /* use these for nameserver config, but also pass onto the test */
            case '4': test_argv[test_argc++] = sourcev4 = optarg;
                      test_argv = realloc(test_argv,
                              (test_argc+1) * sizeof(char*));
                      break;
            case '6': test_argv[test_argc++] = sourcev6 = optarg;
                      test_argv = realloc(test_argv,
                              (test_argc+1) * sizeof(char*));
                      break;
            /* configure ssl certs if we want to talk to a real server */
            case '0': vars.amqp_ssl.cacert = optarg;
                      break;
            case '9': vars.amqp_ssl.cert = optarg;
                      break;
            case '8': vars.amqp_ssl.key = optarg;
                      break;
            /* add any unknown options to a new argv for the test */
            default:  test_argv[test_argc++] = argv[optind-1];
                      test_argv = realloc(test_argv,
                              (test_argc+1) * sizeof(char*));
                      break;
        };
    }

    /* null terminate the new argv for the test */
    test_argv[test_argc] = NULL;

    /* set the nameserver to our custom one if specified */
    if ( nameserver ) {
        /* TODO we could parse the string and get up to MAXNS servers */
        vars.ctx = amp_resolver_context_init(&nameserver, 1, sourcev4,sourcev6);
    } else {
        vars.ctx = amp_resolver_context_init(NULL, 0, sourcev4, sourcev6);
    }

    if ( vars.ctx == NULL ) {
        Log(LOG_ALERT, "Failed to configure resolver, aborting.");
        return -1;
    }

    dests = NULL;
    count = 0;
    pthread_mutex_init(&addrlist_lock, NULL);

    /* process all destinations */
    for ( i=optind; i<argc; i++ ) {
	/* check if adding the new destination would be allowed by the test */
	if ( test_info->max_targets > 0 &&
                (i-optind) >= test_info->max_targets ) {
	    /* ignore any extra destinations but continue with the test */
	    printf("Exceeded max of %d destinations, skipping remainder\n",
		    test_info->max_targets);
	    break;
	}

        amp_resolve_add(vars.ctx, &addrlist, &addrlist_lock, argv[i],
                AF_UNSPEC, -1, &remaining);
    }

    /* wait for all the responses to come in */
    amp_resolve_wait(vars.ctx, &addrlist_lock, &remaining);

    /* add all the results of to the list of destinations */
    for ( rp=addrlist; rp != NULL; rp=rp->ai_next ) {
	if ( test_info->max_targets > 0 && count >= test_info->max_targets ) {
	    /* ignore any extra destinations but continue with the test */
	    printf("Exceeded max of %d destinations, skipping remainder\n",
		    test_info->max_targets);
	    break;
	}
        /* make room for a new destination and fill it */
        dests = realloc(dests, (count + 1) * sizeof(struct addrinfo*));
        dests[count] = rp;
        count++;
    }

    /*
     * Initialise SSL if the test requires a remote server *and* the remote
     * server has been specified as a destination. If it isn't specified then
     * it is probably given as part of the test specific arguments and isn't
     * expecting to talk to an amplet2/measured control port (so don't
     * initialise SSL).
     */
    if ( test_info->server_callback != NULL && count > 0 ) {
        /*
         * These need values for standalone tests to work with remote servers,
         * but there aren't really any good default values we can use. If the
         * user wants to test to a real server, they will need to specify the
         * locations of all the certs/keys/etc.
         */
        /* TODO allow port to be set on command line, watch it doesn't clobber
         * other test options, they are a bit inconsistent!
         */
        vars.control_port = atol(CONTROL_PORT);

        if ( initialise_ssl(&vars.amqp_ssl, NULL) < 0 ) {
            Log(LOG_ALERT, "Failed to initialise SSL, aborting");
            return -1;
        }
        if ( (ssl_ctx = initialise_ssl_context(&vars.amqp_ssl)) == NULL ) {
            Log(LOG_ALERT, "Failed to initialise SSL context, aborting");
            return -1;
        }
    }

    Log(LOG_DEBUG, "test_argc: %d, test_argv:", test_argc);
    for ( i = 0; i < test_argc; i++ ) {
        Log(LOG_DEBUG, "test_argv[%d] = %s\n", i, test_argv[i]);
    }

    /* reset optind so the test can call getopt normally on it's arguments */
    optind = 1;

    /* make sure the RNG is seeded so the tests don't have to worry */
    srandom(time(NULL));

    /* pass arguments and destinations through to the main test run function */
    result = test_info->run_callback(test_argc, test_argv, count, dests);

    if ( result ) {
        test_info->print_callback(result);
        free(result->data);
        free(result);
    }

    amp_resolve_freeaddr(addrlist);


    /* tidy up after ourselves */
    if ( dests ) {
        free(dests);
    }

    free(test_argv);

    ub_ctx_delete(vars.ctx);

    if ( ssl_ctx != NULL ) {
        ssl_cleanup();
    }

    dlclose(test_info->dlhandle);
    free(test_info->name);
    free(test_info);

    return 0;
}
