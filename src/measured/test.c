#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/resource.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/time.h>

#include <libwandevent.h>

#include "config.h"
#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "debug.h"
#include "nametable.h"
#include "modules.h"
#include "global.h" /* hopefully temporary, just to get source iface/address */
#include "ampresolv.h"
#include "ssl.h"
#include "testlib.h"
#include "messaging.h" /* only for report_to_broker() */
#include "controlmsg.h" /* only for write_control_packet() */



/*
 * Combine the test parameters with any from the test set up function and
 * apply them to the proper test binary as provided by the test registration.
 * Run the test callback function and let it do its thing.
 */
void run_test(const test_schedule_item_t * const item, BIO *ctrl) {
    char *argv[MAX_TEST_ARGS];
    uint32_t argc = 0;
    uint32_t offset;
    test_t *test;
    resolve_dest_t *resolve;
    struct addrinfo *addrlist = NULL;
    struct addrinfo **destinations = NULL;
    int total_resolve_count = 0;
    char *packet_delay_str = NULL;
    timer_t watchdog;
    char *dscp_str = NULL;

    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);
    assert((item->dest_count + item->resolve_count) >=
            amp_tests[item->test_id]->min_targets);

    test = amp_tests[item->test_id];

    /* Start the timer so the test will be killed if it runs too long */
    if ( start_test_watchdog(test, &watchdog) < 0 ) {
        Log(LOG_WARNING, "Aborting %s test run", test->name);
        return;
    }

    /* update process name so we can tell what is running */
    set_proc_name(test->name);

    /*
     * seed the random number generator, has to be after the fork() or each
     * new process inherits exactly the same one and always returns the first
     * element in the sequence
     */
    srandom(time(NULL) + getpid());
    reseed_openssl_rng();

    /*
     * TODO should command line arguments clobber any per-test arguments?
     * Currently any arguments set in the schedule file will take precedence.
     */
    argv[argc++] = test->name;

    /* set the inter packet delay if configured at the global level */
    if ( item->meta->inter_packet_delay != MIN_INTER_PACKET_DELAY ) {
        argv[argc++] = "-Z";
        if ( asprintf(&packet_delay_str, "%u",
                    item->meta->inter_packet_delay) < 0 ) {
            Log(LOG_WARNING, "Failed to build packet delay string, aborting");
            stop_watchdog(watchdog);
            return;
        }

        argv[argc++] = packet_delay_str;
    }

    /* TODO don't do these if the test options are already set? */

    /* set the DSCP bits if configured at the global level */
    if ( item->meta->dscp != DEFAULT_DSCP_VALUE ) {
        argv[argc++] = "-Q";
        if ( asprintf(&dscp_str, "%u", item->meta->dscp) < 0 ) {
            Log(LOG_WARNING, "Failed to build DSCP string, aborting");
            return;
        }

        argv[argc++] = dscp_str;
    }

    /* set the outgoing interface if configured at the global level */
    if ( item->meta->interface != NULL ) {
        argv[argc++] = "-I";
        argv[argc++] = item->meta->interface;
    }

    /* set the outgoing source v4 address if configured at the global level */
    if ( item->meta->sourcev4 != NULL ) {
        argv[argc++] = "-4";
        argv[argc++] = item->meta->sourcev4;
    }

    /* set the outgoing source v6 if configured at the global level */
    if ( item->meta->sourcev6 != NULL ) {
        argv[argc++] = "-6";
        argv[argc++] = item->meta->sourcev6;
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
        struct ifaddrs *ifaddrlist;
        int seen_ipv4, seen_ipv6;

	Log(LOG_DEBUG, "test has destinations to resolve!\n");

        /*
         * Check what address families we have available, as there is no
         * point in asking for AAAA records if we can't do IPv6. This looks
         * a lot like __check_pf() from libc that is used by getaddrinfo
         * when AI_ADDRCONFIG is set. Might be nice to do this inside the
         * amp_resolve_add() function, but then it's harder to keep state.
         */
        if ( getifaddrs(&ifaddrlist) < 0 ) {
            /* error getting interfaces, assume we can do both IPv4 and 6 */
            seen_ipv4 = 1;
            seen_ipv6 = 1;
        } else {
            struct ifaddrs *ifa;
            seen_ipv4 = 0;
            seen_ipv6 = 0;
            for ( ifa = ifaddrlist; ifa != NULL; ifa = ifa->ifa_next ) {
                /* some interfaces (e.g. ppp) sometimes won't have an address */
                if ( ifa->ifa_addr == NULL ) {
                    continue;
                }

                /* ignore other interfaces if the source interface is set */
                if ( item->meta->interface != NULL &&
                        strcmp(item->meta->interface, ifa->ifa_name) != 0 ) {
                    continue;
                }

                /* otherwise, flag the family as one that we can use */
                if ( ifa->ifa_addr->sa_family == AF_INET ) {
                    seen_ipv4 = 1;
                } else if ( ifa->ifa_addr->sa_family == AF_INET6 ) {
                    seen_ipv6 = 1;
                }
            }
            freeifaddrs(ifaddrlist);
        }

        /* connect to the local amp resolver/cache */
        if ( (resolver_fd = amp_resolver_connect(vars.nssock)) < 0 ) {
            Log(LOG_ALERT, "TODO tidy up nicely after failing resolving");
            assert(0);
        }

        /* add all the names that we need to resolve */
        for ( resolve=item->resolve; resolve != NULL; resolve=resolve->next ) {
            /* remove any address families that we can't use */
            if ( seen_ipv4 == 0 && resolve->family != AF_INET6 ) {
                if ( resolve->family == AF_INET ) {
                    continue;
                }
                resolve->family = AF_INET6;
            }

            if ( seen_ipv6 == 0 && resolve->family != AF_INET ) {
                if ( resolve->family == AF_INET6 ) {
                    continue;
                }
                resolve->family = AF_INET;
            }

            amp_resolve_add_new(resolver_fd, resolve);
        }

        /* send the flag to mark the end of the list */
        amp_resolve_flag_done(resolver_fd);

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

    /*
     * Only perform the test if there are enough destinations available. Some
     * tests need at least 1 valid destination, others don't require that any
     * destinations are specified.
     */
    if ( item->dest_count + total_resolve_count >= test->min_targets ) {
        amp_test_result_t *result;

	for ( offset = 0; offset<argc; offset++ ) {
	    Log(LOG_DEBUG, "arg%d: %s\n", offset, argv[offset]);
	}

	/* actually run the test */
	result = test->run_callback(argc, argv,
                item->dest_count + total_resolve_count, destinations);

        if ( result ) {
            /* report the results to the appropriate location */
            if ( ctrl ) {
                /* SSL connection - single test run remotely, report remotely */
                write_control_packet(ctrl, result->data, result->len);
            } else {
                /* scheduled test, report to the rabbitmq broker */
                report_to_broker(test->id, result);
            }

            /* free the result structure once it has been reported */
            free(result->data);
            free(result);
        }

	/* free any destinations that we looked up just for this test */
        amp_resolve_freeaddr(addrlist);

	/* just free the temporary list of pointers, leave the actual data */
	if ( destinations != NULL ) {
	    free(destinations);
	}
    }

    /* close the control connection if it exists */
    if ( ctrl ) {
        BIO_free_all(ctrl);
    }

    /* free any command line arguments we had to convert to strings */
    if ( packet_delay_str ) {
        free(packet_delay_str);
    }

    /* unload the watchdog, the test has completed in time */
    stop_watchdog(watchdog);

    if ( dscp_str ) {
        free(dscp_str);
    }

    /* done running the test, exit */
    exit(0);
}



/*
 * Test function to investigate forking, rescheduling, setting maximum
 * execution timers etc.
 * TODO maybe just move the contents of this into run_scheduled_test()?
 */
static int fork_test(test_schedule_item_t *item) {
    struct timeval now;
    pid_t pid;
    test_t *test;

    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);

    test = amp_tests[item->test_id];

    /*
     * Make sure this isn't being run too soon - the monotonic clock and
     * the system time don't generally keep in sync very well (and the system
     * time can get updated from other sources). If we are too early, return
     * without running the test (which will be rescheduled).
     */
    gettimeofday(&now, NULL);
    if ( timercmp(&now, &item->abstime, <) ) {
        timersub(&item->abstime, &now, &now);
        /* run too soon, don't run it now - let it get rescheduled */
        if ( now.tv_sec != 0 || now.tv_usec > SCHEDULE_CLOCK_FUDGE ) {
            Log(LOG_DEBUG, "%s test triggered early, will reschedule",
                    test->name);
            return 0;
        }
    }


    /*
     * man fork:
     * "Under Linux, fork() is implemented using copy-on-write pages..."
     * This should mean that we aren't duplicating massive amounts of memory
     * unless we are modifying it. We shouldn't be modifying it, so should be
     * fine.
     */
    if ( (pid = fork()) < 0 ) {
	perror("fork");
	return 0;
    } else if ( pid == 0 ) {
        /*
         * close the unix domain sockets the parent had, if we keep them open
         * then things can get confusing (test threads end up holding the
         * socket open when it should be closed).
         */
        close(vars.asnsock_fd);
        close(vars.nssock_fd);

        /* unblock signals and remove handlers that the parent process added */
        if ( unblock_signals() < 0 ) {
            Log(LOG_WARNING, "Failed to unblock signals, aborting");
            exit(1);
        }

	run_test(item, NULL);

	Log(LOG_WARNING, "%s test failed to run", test->name);//XXX required?
	exit(1);
    }

    return 1;
}



/*
 * Start a scheduled test running and reschedule it to run again next interval
 */
void run_scheduled_test(wand_event_handler_t *ev_hdl, void *data) {
    schedule_item_t *item = (schedule_item_t *)data;
    test_schedule_item_t *test_item;
    struct timeval next;
    int run;
    char *name;

    assert(item->type == EVENT_RUN_TEST);

    test_item = (test_schedule_item_t *)item->data.test;
    name = amp_tests[test_item->test_id]->name;

    Log(LOG_DEBUG, "Running %s test", name);
    printf("running %s test at %d\n", name, (int)time(NULL));

    /*
     * run the test as soon as we know what it is, so it happens as close to
     * the right time as we can get it.
     */
    run = fork_test(test_item);

    /* while the test runs, reschedule it again */
    next = get_next_schedule_time(item->ev_hdl, test_item->period,
            test_item->start, test_item->end, US_FROM_TV(test_item->interval),
            run, &test_item->abstime);

    if ( wand_add_timer(ev_hdl, next.tv_sec, next.tv_usec, data,
                run_scheduled_test) == NULL ) {
        /* this should never happen if we properly check the next time */
        Log(LOG_ALERT, "Failed to reschedule %s test", name);
    }
}
