#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/resource.h>
#include <string.h>

#include <libwandevent.h>

#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "debug.h"
#include "nametable.h"
#include "modules.h"
#include "global.h" /* hopefully temporary, just to get source iface/address */
#include "ampresolv.h"



/*
 * Combine the test parameters with any from the test set up function and
 * apply them to the proper test binary as provided by the test registration.
 * Run the test callback function and let it do its thing.
 */
static void run_test(const test_schedule_item_t * const item) {
    char *argv[MAX_TEST_ARGS];
    uint32_t argc = 0;
    uint32_t offset;
    test_t *test;
    resolve_dest_t *resolve;
    struct addrinfo *addrlist = NULL;
    struct addrinfo **destinations = NULL;
    int total_resolve_count = 0;

    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);
    assert((item->dest_count + item->resolve_count) > 0);

    /*
     * seed the random number generator, has to be after the fork() or each
     * new process inherits exactly the same one and always returns the first
     * element in the sequence
     */
    srandom(time(NULL));

    test = amp_tests[item->test_id];
    argv[argc++] = test->name;

    /* set the outgoing interface if configured at the global level */
    if ( vars.interface != NULL ) {
        argv[argc++] = "-I";
        argv[argc++] = vars.interface;
    }

    /* set the outgoing source v4 address if configured at the global level */
    if ( vars.sourcev4 != NULL ) {
        argv[argc++] = "-4";
        argv[argc++] = vars.sourcev4;
    }

    /* set the outgoing source v6 if configured at the global level */
    if ( vars.sourcev6 != NULL ) {
        argv[argc++] = "-6";
        argv[argc++] = vars.sourcev6;
    }

    /* add in any of the test parameters from the schedule file */
    if ( item->params != NULL ) {
	for ( offset=0; item->params[offset] != NULL; offset++ ) {
	    argv[argc++] = item->params[offset];
	}
    }

    /* null terminate the list before we give it to the main test function */
    argv[argc] = NULL;

    Log(LOG_DEBUG, "Running test: %s to %d/%d destinations:\n", test->name,
	    item->dest_count, item->resolve_count);

    /* create the destination list for the test if there are fixed targets */
    if ( item->dest_count > 0 ) {
	destinations = malloc(sizeof(struct addrinfo*) * item->dest_count);

	/* copy all currently resolved destination pointers as a block */
	memcpy(destinations, item->dests,
		sizeof(struct addrinfo*) * item->dest_count);
    }

    /* resolve any names that need to be done at test run time */
    if ( item->resolve != NULL ) {
	struct addrinfo *tmp;
        int resolver_fd;

	Log(LOG_DEBUG, "test has destinations to resolve!\n");

        /* connect to the local amp resolver/cache */
        if ( (resolver_fd = amp_resolver_connect(vars.nssock)) < 0 ) {
            Log(LOG_ALERT, "TODO tidy up nicely after failing resolving");
            assert(0);
        }

        /* add all the names that we need to resolve */
        for ( resolve=item->resolve; resolve != NULL; resolve=resolve->next ) {
            amp_resolve_add_new(resolver_fd, resolve);
        }

        /* get the list of all the addresses the names resolved to (blocking) */
        addrlist = amp_resolve_get_list(resolver_fd);

        /* create the destination list from all the resolved addresses */
        for ( tmp = addrlist; tmp != NULL; tmp = tmp->ai_next ) {
            destinations = realloc(destinations,
                    (item->dest_count + total_resolve_count + 1) *
                    sizeof(struct addrinfo));
            destinations[item->dest_count + total_resolve_count] = tmp;
            total_resolve_count++;
        }
    }

    Log(LOG_DEBUG, "Final destination count = %d\n",
	    item->dest_count + total_resolve_count);

    /* only perform the test if there are actually destinations to test to */
    if ( item->dest_count + total_resolve_count > 0 ) {
	//Log(LOG_DEBUG, "dest%d: %s\n", offset,
	//	    address_to_name(item->dests[offset]));

	for ( offset = 0; offset<argc; offset++ ) {
	    Log(LOG_DEBUG, "arg%d: %s\n", offset, argv[offset]);
	}

        /* TODO set up any servers that need to be setup? or allow the tests
         * to do that themselves? We've already forked so we aren't holding
         * anyone up, but who makes more sense to control this?
         */

	/* actually run the test */
	test->run_callback(argc, argv, item->dest_count + total_resolve_count,
		destinations);

	/* free any destinations that we looked up just for this test */
        amp_resolve_freeaddr(addrlist);

	/* just free the temporary list of pointers, leave the actual data */
	if ( destinations != NULL ) {
	    free(destinations);
	}
    }

    /* done running the test, exit */
    exit(0);
}



/*
 * Test function to investigate forking, rescheduling, setting maximum
 * execution timers etc.
 * TODO maybe just move the contents of this into run_scheduled_test()?
 */
static void fork_test(wand_event_handler_t *ev_hdl,test_schedule_item_t *item) {
    pid_t pid;
    test_t *test;

    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);

    test = amp_tests[item->test_id];

    /*
     * man fork:
     * "Under Linux, fork() is implemented using copy-on-write pages..."
     * This should mean that we aren't duplicating massive amounts of memory
     * unless we are modifying it. We shouldn't be modifying it, so should be
     * fine.
     */
    if ( (pid = fork()) < 0 ) {
	perror("fork");
	return;
    } else if ( pid == 0 ) {
	/* child, prepare the environment and run the test functions */
	//struct rlimit cpu_limits;
	//cpu_limits.rlim_cur = 60;
	//cpu_limits.rlim_max = 60;
	/* XXX if this kills a test, how to distinguish it from the watchdog
	 * doing so? in this case the watchdog timer still needs to be removed
	 */
	//setrlimit(RLIMIT_CPU, &cpu_limits);
	/* TODO prepare environment */
	run_test(item);
	Log(LOG_WARNING, "%s test failed to run", test->name);//XXX required?
	exit(1);
    }

    //XXX if the test aborts before we add this, will that cock things up?
    /* schedule the watchdog to kill it if it takes too long */
    add_test_watchdog(ev_hdl, pid, test->max_duration, test->name);
}



/*
 * Start a scheduled test running and reschedule it to run again next interval
 */
void run_scheduled_test(struct wand_timer_t *timer) {
    schedule_item_t *item = (schedule_item_t *)timer->data;
    test_schedule_item_t *data;
    struct timeval next;

    assert(item->type == EVENT_RUN_TEST);

    data = (test_schedule_item_t *)item->data.test;

    Log(LOG_DEBUG, "Running a %s test", amp_tests[data->test_id]->name);
    printf("running a %s test at %d\n", amp_tests[data->test_id]->name,
	    (int)time(NULL));

    /*
     * run the test as soon as we know what it is, so it happens as close to
     * the right time as we can get it.
     */
    fork_test(item->ev_hdl, data);

    /* while the test runs, reschedule it again */
    next = get_next_schedule_time(item->ev_hdl, data->repeat, data->start,
	    data->end, MS_FROM_TV(data->interval));
    timer->expire = wand_calc_expire(item->ev_hdl, next.tv_sec, next.tv_usec);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(item->ev_hdl, timer);
}
