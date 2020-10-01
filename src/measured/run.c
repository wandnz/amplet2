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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <event2/event.h>
#include <fcntl.h>
#include <stdint.h>

#if _WIN32
#include "w32-compat.h"
#else
#include <ifaddrs.h>
#include <sys/socket.h>
#endif

#include "config.h"
#include "schedule.h"
#include "watchdog.h"
#include "run.h"
#include "control.h"
#include "debug.h"
#include "nametable.h"
#include "modules.h"
#include "global.h" /* hopefully temporary */
#include "ampresolv.h"
#include "ssl.h"
#include "messaging.h"
#include "serverlib.h" /* only for send_measured_response() */



/*
 * Combine the test parameters with any from the test set up function and
 * apply them to the proper test binary as provided by the test registration.
 * Run the test callback function and let it do its thing.
 */
void run_test(const test_schedule_item_t * const item, BIO *ctrl) {
    char *argv[MAX_TEST_ARGS];
    uint32_t argc = 0;
    uint32_t offset;
    resolve_dest_t *resolve;
    struct addrinfo *addrlist = NULL;
    struct addrinfo **destinations = NULL;
    int total_resolve_count = 0;
    char *packet_delay_str = NULL;
    timer_t watchdog;
    char *dscp_str = NULL;
    char *port_str = NULL;
    int forcev4 = 0;
    int forcev6 = 0;

    assert(item);
    assert(item->test);
    assert((item->dest_count + item->resolve_count) >= item->test->min_targets);

    /* Start the timer so the test will be killed if it runs too long */
    /* XXX should this start before or after DNS resolution, maybe after? */
    if ( start_test_watchdog(item->test, &watchdog) < 0 ) {
        Log(LOG_WARNING, "Aborting %s test run", item->test->name);
        return;
    }

    /* update process name so we can tell what is running */
    set_proc_name(item->test->name);

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
    argv[argc++] = item->test->name;

    /* set the inter packet delay if configured at the global level */
    if ( item->meta->inter_packet_delay != MIN_INTER_PACKET_DELAY ) {
        argv[argc++] = "-Z";
        if ( asprintf(&packet_delay_str, "%u",
                    item->meta->inter_packet_delay) < 0 ) {
            Log(LOG_WARNING, "Failed to build packet delay string, aborting");
            stop_watchdog(watchdog);
            free_duped_environ();
            return;
        }

        argv[argc++] = packet_delay_str;
    }

    /* TODO don't do these if the test options are already set? */

    /* set the control port if configured at the global level */
    if ( item->test->server_callback &&
            vars.control_port != atol(DEFAULT_AMPLET_CONTROL_PORT) ) {
        argv[argc++] = "-p";
        if ( asprintf(&port_str, "%u", vars.control_port) < 0 ) {
            Log(LOG_WARNING, "Failed to build control port string, aborting");
            stop_watchdog(watchdog);
            free_duped_environ();
            return;
        }

        argv[argc++] = port_str;
    }

    /* set the DSCP bits if configured at the global level */
    if ( item->meta->dscp != DEFAULT_DSCP_VALUE ) {
        argv[argc++] = "-Q";
        if ( asprintf(&dscp_str, "%u", item->meta->dscp) < 0 ) {
            Log(LOG_WARNING, "Failed to build DSCP string, aborting");
            stop_watchdog(watchdog);
            free_duped_environ();
            return;
        }

        argv[argc++] = dscp_str;
    }

    /* set the outgoing interface if configured at the global level */
    if ( item->meta->iface != NULL ) {
        argv[argc++] = "-I";
        argv[argc++] = item->meta->iface;
    }

    /* set the outgoing source v4 address if configured at the global level */
    if ( item->meta->sourcev4 != NULL ) {
        forcev4 = 1;
        argv[argc++] = "-4";
        if ( strcmp(item->meta->sourcev4, "any") != 0 ) {
            argv[argc++] = item->meta->sourcev4;
        }
    }

    /* set the outgoing source v6 if configured at the global level */
    if ( item->meta->sourcev6 != NULL ) {
        forcev6 = 1;
        argv[argc++] = "-6";
        if ( strcmp(item->meta->sourcev6, "any") != 0 ) {
            argv[argc++] = item->meta->sourcev6;
        }
    }

    /* add in any of the test parameters from the schedule file */
    if ( item->params != NULL ) {
	for ( offset=0; item->params[offset] != NULL; offset++ ) {
	    argv[argc++] = item->params[offset];
            /* limit resolving address family if the test requires */
            if ( strcmp(item->params[offset], "-4") == 0 ) {
                forcev4 = 1;
            } else if ( strcmp(item->params[offset], "-6") == 0 ) {
                forcev6 = 1;
            }
	}
    }

    /* null terminate the list before we give it to the main test function */
    argv[argc] = NULL;

    Log(LOG_DEBUG, "Running test: %s to %d/%d destinations:\n",
            item->test->name, item->dest_count, item->resolve_count);

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
        int seen_ipv4 = 0;
        int seen_ipv6 = 0;

	Log(LOG_DEBUG, "test has destinations to resolve!\n");

#if _WIN32
        /* TODO determine if ipv6 is available */
        seen_ipv4 = 1;
#else
        /*
         * Check what address families we have available, as there is no
         * point in asking for AAAA records if we can't do IPv6. This looks
         * a lot like __check_pf() from libc that is used by getaddrinfo
         * when AI_ADDRCONFIG is set. Might be nice to do this inside the
         * amp_resolve_add() function, but then it's harder to keep state.
         */
        if ( forcev4 && !forcev6 ) {
            seen_ipv4 = 1;
            seen_ipv6 = 0;
        } else if ( forcev6 && !forcev4 ) {
            seen_ipv4 = 0;
            seen_ipv6 = 1;
        } else if ( getifaddrs(&ifaddrlist) < 0 ) {
            /* error getting interfaces, assume we can do both IPv4 and 6 */
            seen_ipv4 = 1;
            seen_ipv6 = 1;
        } else {
            struct ifaddrs *ifa;
            for ( ifa = ifaddrlist; ifa != NULL; ifa = ifa->ifa_next ) {
                /* some interfaces (e.g. ppp) sometimes won't have an address */
                if ( ifa->ifa_addr == NULL ) {
                    continue;
                }

                /* ignore other interfaces if the source interface is set */
                if ( item->meta->iface != NULL &&
                        strcmp(item->meta->iface, ifa->ifa_name) != 0 ) {
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
#endif

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
    if ( item->dest_count + total_resolve_count >= item->test->min_targets ) {
        amp_test_result_t *result;

        for ( offset = 0; offset<argc; offset++ ) {
	    Log(LOG_DEBUG, "arg%d: %s\n", offset, argv[offset]);
	}

        /*
         * TODO tests can exit() in bad situations rather than returning data,
         * which means none of this code will be run. Should all tests return
         * something useful and never exit themselves?
         */
        /* actually run the test */
        result = item->test->run_callback(argc, argv,
                item->dest_count + total_resolve_count, destinations);

        if ( result ) {
            /* report the results to the appropriate location */
            if ( ctrl ) {
                /* SSL connection - single test run remotely, report remotely */
                send_measured_result(ctrl, item->test->id, result);
            } else {
                /* scheduled test, report to the rabbitmq broker */
                report_to_broker(item->test, result);
            }

            /* free the result structure once it has been reported */
            free(result->data);
            free(result);

        } else if ( ctrl ) {
            /* TODO report the reason, might have lacked SERVER permissions.
             * This might mean tests need to return a control message
             * rather than a result structure?
             */
            send_measured_response(ctrl, MEASURED_CONTROL_FAILED, "No result");
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

    if ( port_str ) {
        free(port_str);
    }

    /* free the environment duped by set_proc_name() */
    free_duped_environ();

#if _WIN32
    ExitThread(EXIT_SUCCESS);
#else
    exit(EXIT_SUCCESS);
#endif
}



#if _WIN32
static long unsigned int run_test_w32(void *data) {
    test_schedule_item_t *item = (test_schedule_item_t*)data;

#if 0
    /* XXX threads probably don't want to do this? */
    close(vars.asnsock_fd);
    close(vars.nssock_fd);

    /* unblock signals and remove handlers that the parent process added */
    if ( unblock_signals() < 0 ) {
        Log(LOG_WARNING, "Failed to unblock signals, aborting");
        exit(EXIT_FAILURE);
    }

    /* XXX threads probably don't want to do this? */
    clear_test_schedule(item->meta->base, 1);
    event_base_free(item->meta->base);
#endif

    run_test(item, NULL);

    Log(LOG_WARNING, "%s test failed to run", item->test->name);
    ExitThread(EXIT_FAILURE);
}
#endif



/*
 * Test function to investigate forking, rescheduling, setting maximum
 * execution timers etc.
 * TODO maybe just move the contents of this into run_scheduled_test()?
 */
static int fork_test(test_schedule_item_t *item) {
    struct timeval now;
    pid_t pid;

    assert(item);
    assert(item->test);

    /*
     * Make sure this isn't being run too soon - the monotonic clock and
     * the system time don't generally keep in sync very well (and the system
     * time can get updated from other sources). If we are too early, return
     * without running the test (which will be rescheduled).
     */
    gettimeofday(&now, NULL);
    if ( timercmp(&now, &item->abstime, <) ) {
        evutil_timersub(&item->abstime, &now, &now);
        /* run too soon, don't run it now - let it get rescheduled */
        if ( now.tv_sec != 0 || now.tv_usec > SCHEDULE_CLOCK_FUDGE ) {
            Log(LOG_DEBUG, "%s test triggered early, will reschedule",
                    item->test->name);
            return 0;
        }
    }

#if _WIN32
    CreateThread(NULL,
            0,
            run_test_w32,
            item,
            0,
            NULL);
#else
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
            exit(EXIT_FAILURE);
        }
        /*
         * libevent can have issues spooling up another event loop from within
         * an existing event loop, so need to free current base before we can
         * register a new one
         */
        clear_test_schedule(item->meta->base, 1);
        event_base_free(item->meta->base);

        run_test(item, NULL);

        Log(LOG_WARNING, "%s test failed to run", item->test->name);
        exit(EXIT_FAILURE);
    }
#endif

    return 1;
}



/*
 * Start a scheduled test running and reschedule it to run again next interval
 */
void run_scheduled_test(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void *evdata) {
    schedule_item_t *item = (schedule_item_t *)evdata;
    test_schedule_item_t *test_item;
    struct timeval next;
    int run;

    assert(item->type == EVENT_RUN_TEST);

    test_item = (test_schedule_item_t *)item->data.test;

    Log(LOG_DEBUG, "Running %s test", test_item->test->name);
    printf("running %s test at %d\n", test_item->test->name, (int)time(NULL));

    /*
     * run the test as soon as we know what it is, so it happens as close to
     * the right time as we can get it.
     */
    run = fork_test(test_item);

    /* while the test runs, reschedule it again */
    next = get_next_schedule_time(item->base, test_item->period,
            test_item->start, test_item->end, US_FROM_TV(test_item->interval),
            run, &test_item->abstime);

    if ( event_add(item->event, &next) != 0 ) {
        /* this should never happen if we properly check the next time */
        Log(LOG_ALERT, "Failed to reschedule %s test", test_item->test->name);
    }
}
