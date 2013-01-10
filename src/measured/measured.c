/*
 * src/measured/measured.c
 * Main controlling code for the core of measured
 *
 * Primary tasks:
 *  - test scheduling (keep up to date with schedule, run tests at right times)
 *  - set up environment and fork test processes
 *  - set up and maintain control (and reporting?) sockets
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>


#if HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

#include <libwandevent.h>
#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "nametable.h"
#include "daemonise.h"
#include "debug.h"
#include "messaging.h"

wand_event_handler_t *ev_hdl;



/*
 * Print a simple usage statement showing how to run the program.
 */
static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [-dvx]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemonise   Detach and run in background\n");
    fprintf(stderr, "  -v, --version     Print version information and exit\n");
    fprintf(stderr, "  -x, --debug       Enable extra debug output\n");
}



/*
 * Set the flag that will cause libwandevent to stop running the main event
 * loop and return control to us.
 */
static void stop_running(__attribute__((unused))struct wand_signal_t *signal) {
    Log(LOG_INFO, "Received SIGINT, exiting event loop");
    ev_hdl->running = false;
}



/*
 * If measured gets sent a SIGHUP then it should reload all the available
 * test modules and then re-read the schedule file taking into account the
 * new list of available tests.
 */
static void reload(__attribute__((unused))struct wand_signal_t *signal) {
    Log(LOG_INFO, "Received SIGHUP, reloading all configuration");

    /* cancel all scheduled tests (let running ones finish) */
    clear_test_schedule(signal->data);

    /* reload all test modules */
    unregister_tests();
    if ( register_tests(AMP_TEST_DIRECTORY) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	exit(1);
    }

    /* re-read schedule file */
    read_schedule_file(signal->data);
}



/*
 *
 */
int main(int argc, char *argv[]) {
    struct wand_signal_t sigint_ev;
    struct wand_signal_t sigchld_ev;
    struct wand_signal_t sighup_ev;

    while ( 1 ) {
	static struct option long_options[] = {
	    {"daemonise", no_argument, 0, 'd'},
	    {"daemonize", no_argument, 0, 'd'},
	    {"help", no_argument, 0, 'h'},
	    {"version", no_argument, 0, 'v'},
	    {"debug", no_argument, 0, 'x'},
	    {0, 0, 0, 0}
	};

	int opt_ind = 0;
	int c = getopt_long(argc, argv, "dhvx", long_options, &opt_ind);
	if ( c == -1 )
	    break;

	switch ( c ) {
	    case 'd':
		/* daemonise, detach, close stdin/out/err, etc */
		if ( daemon(0, 0) < 0 ) {
		    perror("daemon");
		    return -1;
		}
		break;
	    case 'v':
		/* TODO print version info */
		break;
	    case 'x':
		/* enable extra debug output */
		log_level = LOG_DEBUG;
		break;
	    case 'h':
	    default:
		usage(argv[0]);
		exit(0);
	};
    }
    
    Log(LOG_INFO, "measured starting");

    /* reset optind so the tests can call getopt normally on it's arguments */
    optind = 1;

    /* establish a connection to the broker that all tests will use */
    connect_to_broker();

    /* load all the test modules */
    if ( register_tests(AMP_TEST_DIRECTORY) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	return -1;
    }

    /* set up event handlers */
    wand_event_init();
    ev_hdl = wand_create_event_handler();
    assert(ev_hdl);

    /* set up a handler to deal with SIGINT so we can shutdown nicely */
    sigint_ev.signum = SIGINT;
    sigint_ev.callback = stop_running;
    sigint_ev.data = NULL;
    wand_add_signal(&sigint_ev);
    
    /* set up handler to deal with SIGCHLD so we can tidy up after tests */
    sigchld_ev.signum = SIGCHLD;
    sigchld_ev.callback = child_reaper;
    sigchld_ev.data = ev_hdl;
    wand_add_signal(&sigchld_ev);
    
    /* set up handler to deal with SIGHUP to reload available tests */
    sighup_ev.signum = SIGHUP;
    sighup_ev.callback = reload;
    sighup_ev.data = ev_hdl;
    wand_add_signal(&sighup_ev);

    /* read the nametable to get a list of all test targets */
    read_nametable_file();
    /* check for changes to the nametable file forever */
    setup_nametable_refresh(ev_hdl);

    /* read the schedule file to create the initial test schedule */
    read_schedule_file(ev_hdl);
    /* check for any changes to the schedule file forever */
    setup_schedule_refresh(ev_hdl);
    
    /* give up control to libwandevent */
    wand_event_run(ev_hdl);

    /* if we get control back then it's time to tidy up */
    /* TODO clear schedule refresher */
    /* TODO what to do about scheduled tasks such as watchdogs? */
    clear_test_schedule(ev_hdl);
    clear_nametable();
    wand_del_signal(&sigint_ev);
    wand_del_signal(&sigchld_ev);
    wand_del_signal(&sighup_ev);
    wand_destroy_event_handler(ev_hdl);

    /* clear out all the test modules that were registered */
    unregister_tests();

    /* cleanly tear down the connection to the broker */
    close_broker_connection(); 

    Log(LOG_INFO, "Shutting down");

    return 0;
}
