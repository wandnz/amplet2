/*
 * src/xferd/xferd.c
 * Main controlling code for the core of xferd
 *
 * Primary tasks:
 *  - consume messages from the rabbitmq broker
 *  - write them to storage in a useful way
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <confuse.h>
#include <string.h>

#include "tests.h"
#include "daemonise.h"
#include "debug.h"
#include "messaging.h"
#include "consumer.h"
#include "modules.h"
#include "global.h"



/*
 * Print a simple usage statement showing how to run the program.
 */
static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [-dvx] [-c <config>]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemonise   Detach and run in background\n");
    fprintf(stderr, "  -v, --version     Print version information and exit\n");
    fprintf(stderr, "  -x, --debug       Enable extra debug output\n");
    fprintf(stderr, "  -c <config>       Specify config file\n");
}



/*
 * Set the flag that will cause the consumer loop to stop running and return 
 * control to us.
 */
static void stop_running(__attribute__((unused))int signum) {
    Log(LOG_INFO, "Received SIGINT, exiting consumer loop");
    running = 0;
}



/*
 *
 */
static int parse_config(char *filename, struct amp_global_t *vars) {
    int ret;
    cfg_t *cfg;
    cfg_opt_t measured_opts[] = {
	/* TODO location of test modules? */
	/* TODO location of certificate files? */
	CFG_STR("testdir", AMP_TEST_DIRECTORY, CFGF_NONE),
	CFG_STR("exchange", "amp_exchange", CFGF_NONE),
	CFG_STR("routingkey", "test", CFGF_NONE),
	CFG_END()
    };

    Log(LOG_INFO, "Parsing configuration file %s\n", filename);

    cfg = cfg_init(measured_opts, CFGF_NONE);
    ret = cfg_parse(cfg, filename);
    
    if ( ret == CFG_FILE_ERROR ) {
	cfg_free(cfg);
	Log(LOG_ALERT, "No such config file '%s', aborting.", filename);
	return -1;
    }

    if ( ret == CFG_PARSE_ERROR ) {
	cfg_free(cfg);
	Log(LOG_ALERT, "Failed to parse config file '%s', aborting.", 
		filename);
	return -1;
    }

    vars->testdir = strdup(cfg_getstr(cfg, "testdir"));
    vars->exchange = strdup(cfg_getstr(cfg, "exchange"));
    vars->routingkey = strdup(cfg_getstr(cfg, "routingkey"));

    cfg_free(cfg);
    return 0;
}



/*
 *
 */
int main(int argc, char *argv[]) {

    struct sigaction action;
    char *config_file = NULL;

    while ( 1 ) {
	static struct option long_options[] = {
	    {"daemonise", no_argument, 0, 'd'},
	    {"daemonize", no_argument, 0, 'd'},
	    {"help", no_argument, 0, 'h'},
	    {"version", no_argument, 0, 'v'},
	    {"debug", no_argument, 0, 'x'},
	    {"config", required_argument, 0, 'c'},
	    {0, 0, 0, 0}
	};

	int opt_ind = 0;
	int c = getopt_long(argc, argv, "dhvxc:", long_options, &opt_ind);
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
	    case 'c':
		/* specify a configuration file */
		config_file = optarg;
		break;
	    case 'h':
	    default:
		usage(argv[0]);
		exit(0);
	};
    }
    
    Log(LOG_INFO, "xferd starting");

    if ( !config_file ) {
	config_file = AMP_CONFIG_DIR "/xferd.conf";
    }
    
    if ( parse_config(config_file, &vars) < 0 ) {
	return -1;
    }

    /* set up SIGINT handler to tidy up nicely */
    action.sa_handler = stop_running;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction(SIGINT, &action, NULL);

    /* establish a connection to the broker that all consumers will use */
    connect_to_broker();

    /* load all the test modules */
    if ( register_tests(vars.testdir) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	return -1;
    }

    /* start the main consumer loop, will go forever */
    consumer();

    /* clear out all the test modules that were registered */
    unregister_tests();
    
    /* cleanly tear down the connection to the broker */
    close_broker_connection(); 

    Log(LOG_INFO, "Shutting down");

    return 0;
}
