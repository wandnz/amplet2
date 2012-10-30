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


#if HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

#include <libwandevent.h>
#include "schedule.h"
#include "watchdog.h"

wand_event_handler_t *ev_hdl;

static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [-dvx]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemonise   Detach and run in background\n");
    fprintf(stderr, "  -v, --version     Print version information and exit\n");
    fprintf(stderr, "  -x, --debug       Enable extra debug output\n");
}



/*
 *
 */
static void stop_running(__attribute__((unused))struct wand_signal_t *signal) {
    ev_hdl->running = false;
}



/*
 *
 */
int main(int argc, char *argv[]) {
    struct wand_signal_t signal_ev;

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
		/* TODO daemonise */
		break;
	    case 'v':
		/* TODO print version info */
		break;
	    case 'x':
		/* TODO enable extra debug output */
		break;
	    case 'h':
	    default:
		usage(argv[0]);
		exit(0);
	};
    }


    /* set up event handlers */
    wand_event_init();
    ev_hdl = wand_create_event_handler();
    assert(ev_hdl);

    /* set up a handler to deal with SIGINT so we can shutdown nicely */
    signal_ev.signum = SIGINT;
    signal_ev.callback = stop_running;
    signal_ev.data = NULL;
    wand_add_signal(&signal_ev);
    
    struct wand_signal_t signal_ev2;
    signal_ev2.signum = SIGCHLD;
    signal_ev2.callback = child_reaper;
    signal_ev2.data = NULL;
    wand_add_signal(&signal_ev2);

    /* read the schedule file to create the initial test schedule */
    read_schedule_file(ev_hdl);
    /* check for any changes to the schedule file forever */
    setup_schedule_refresh(ev_hdl);
    
    /* give up control to libwandevent */
    wand_event_run(ev_hdl);

    /* if we get control back then it's time to tidy up */
    /* TODO clear schedule refresher */
    /* TODO clear schedule */
    wand_del_signal(&signal_ev);
    wand_destroy_event_handler(ev_hdl);

    return 0;
}
