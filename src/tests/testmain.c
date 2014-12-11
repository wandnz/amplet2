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
    struct addrinfo *addrlist = NULL, *rp;
    int log_flag_index, ns_flag_index;
    int count;
    int opt;
    int i;
    char *nameserver = NULL;
    int remaining = 0;
    pthread_mutex_t addrlist_lock;

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

    log_flag_index = 0;
    ns_flag_index = 0;

    /*
     * deal with command line arguments - split them into actual arguments
     * and destinations in the style the AMP tests want. Using "-" as the
     * optstring means that non-option arguments are treated as having an
     * option with character code 1 (which prevents them from being shuffled
     * to the end of the list). All test arguments will be preserved, and the
     * destinations listed after the -- marker can be removed easily.
     */
    while ( (opt = getopt(argc, argv, "-xD:I:4:6:")) != -1 ) {
	/* generally do nothing, just use up arguments until the -- marker */
        switch ( opt ) {
            /* -x is the only option we care about for now - enable debug */
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      log_flag_index = optind - 1;
                      break;
            /* set these in global vars array so start_remote_server works */
            case 'I': vars.interface = optarg; break;
            case '4': vars.sourcev4 = optarg; break;
            case '6': vars.sourcev6 = optarg; break;
            case 'D': nameserver = optarg; ns_flag_index = optind - 2; break;
            default: /* do nothing */ break;
        };
    }

    /* set the nameserver to our custom one if specified */
    if ( nameserver ) {
        /* TODO we could parse the string and get up to MAXNS servers */
        vars.ctx = amp_resolver_context_init(&nameserver, 1, vars.sourcev4,
                vars.sourcev6);
    } else {
        vars.ctx = amp_resolver_context_init(NULL, 0, vars.sourcev4,
                vars.sourcev6);
    }

    if ( vars.ctx == NULL ) {
        Log(LOG_ALERT, "Failed to configure resolver, aborting.");
        return -1;
    }

    dests = NULL;
    count = 0;
    pthread_mutex_init(&addrlist_lock, NULL);

    /* process all destinations */
    /* TODO prevent duplicate destinations? */
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
         * but there aren't really any good default values we can use. The
         * current values give us a way to make it work if we need to, but
         * it's not very nice.
         * TODO either parse the config file, or require them to be set from
         * the command line?
         */
        vars.amqp_ssl.keys_dir = AMP_KEYS_DIR "/default";
        vars.collector = "default";
        vars.control_port = "8869"; /* XXX */

        if ( initialise_ssl(&vars.amqp_ssl, vars.collector) < 0 ) {
            Log(LOG_ALERT, "Failed to initialise SSL, aborting");
            return -1;
        }
        if ( (ssl_ctx = initialise_ssl_context(&vars.amqp_ssl)) == NULL ) {
            Log(LOG_ALERT, "Failed to initialise SSL context, aborting");
            return -1;
        }
    }

    /* remove the -x option if present so that the test doesn't see it */
    if ( log_level_override && log_flag_index > 0 ) {
        memmove(argv + log_flag_index, argv + log_flag_index + 1,
                (argc - log_flag_index - 1) * sizeof(char *));
        optind--;
        /* adjust the nameserver arguments along as well to fill the gap */
        if ( ns_flag_index > log_flag_index ) {
            ns_flag_index--;
        }
    }

    /* remove the -D nameserver option too, so the test doesn't see it */
    if ( nameserver && ns_flag_index > 0 ) {
        memmove(argv + ns_flag_index, argv + ns_flag_index + 2,
                (argc - ns_flag_index - 2) * sizeof(char *));
        optind -= 2;
    }

    /* prematurely terminate argv so the test doesn't see the destinations */
    argv[optind] = NULL;
    argc = optind;

    /* reset optind so the test can call getopt normally on it's arguments */
    optind = 1;

    /* make sure the RNG is seeded so the tests don't have to worry */
    srandom(time(NULL));

    /* pass arguments and destinations through to the main test run function */
    test_info->run_callback(argc, argv, count, dests);

    amp_resolve_freeaddr(addrlist);

    /* tidy up after ourselves */
    if ( dests ) {
        free(dests);
    }

    ub_ctx_delete(vars.ctx);

    if ( ssl_ctx != NULL ) {
        ssl_cleanup();
    }

    dlclose(test_info->dlhandle);
    free(test_info->name);
    free(test_info);

    return 0;
}
