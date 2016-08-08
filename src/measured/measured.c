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

#include <stdio.h>
#include <getopt.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <amqp_ssl_socket.h>

#include <curl/curl.h>
#include <libwandevent.h>
#include "schedule.h"
#include "watchdog.h"
#include "nametable.h"
#include "debug.h"
#include "modules.h"
#include "global.h"
#include "control.h"
#include "ssl.h"
#include "testlib.h"
#include "rabbitcfg.h"
#include "nssock.h"
#include "asnsock.h"
#include "localsock.h"
#include "certs.h"
#include "parseconfig.h"

#define AMP_CLIENT_CONFIG_DIR AMP_CONFIG_DIR "/clients"


static struct option long_options[] = {
    {"daemonise", no_argument, 0, 'd'},
    {"daemonize", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {"config", required_argument, 0, 'c'},
    {"noremote", required_argument, 0, 'r'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", required_argument, 0, '4'},
    {"ipv6", required_argument, 0, '6'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {0, 0, 0, 0}
};



/*
 * Print a simple usage statement showing how to run the program.
 */
static void usage(void) {

    fprintf(stderr, "Usage: amplet2 [-dvxr] [-c <config>] [-I <iface>]\n"
            "               [-4 <address>] [-6 <address>]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemonise                Detach and run in background\n");
    fprintf(stderr, "  -v, --version                  Print version information and exit\n");
    fprintf(stderr, "  -x, --debug                    Enable extra debug output\n");
    fprintf(stderr, "  -c, --config         <config>  Specify config file\n");
    fprintf(stderr, "  -r, --noremote                 Don't fetch remote schedules\n");
    fprintf(stderr, "  -I, --interface      <iface>   Override source interface name\n");
    fprintf(stderr, "  -Z, --interpacketgap <usec>    Minimum number of microseconds between packets\n");
    fprintf(stderr, "  -4, --ipv4           <address> Override source IPv4 address\n");
    fprintf(stderr, "  -6, --ipv6           <address> Override source IPv6 address\n");
}



static void print_measured_version(char *prog) {
    printf("%s (%s)\n", prog, PACKAGE_STRING);
    printf("Report bugs to <%s>\n", PACKAGE_BUGREPORT);
    printf(" config dir: %s\n", AMP_CONFIG_DIR);
    printf(" client config dir: %s\n", AMP_CLIENT_CONFIG_DIR);
    printf(" schedule config dir: %s\n", SCHEDULE_DIR);
    printf(" nametable config dir: %s\n", NAMETABLE_DIR);
    printf(" test library dir: %s\n", AMP_TEST_DIRECTORY);
}



/*
 * Create a pidfile and put the pid of the current process into it. Lock it
 * so that another instance of the program can easily tell that it is already
 * running.
 */
static int create_pidfile(char *pidfile) {
    int fd;
    char buf[128];

    assert(pidfile);

    Log(LOG_DEBUG, "Creating pidfile '%s'", pidfile);

    /*
     * Open pid file (creating if needed) and set to close on exec. Don't
     * truncate it or anything similar, as we don't want to touch it until
     * after we have got a lock on it.
     */
    if ( (fd = open(pidfile, O_RDWR | O_CREAT | O_CLOEXEC,
                    S_IRUSR | S_IWUSR)) < 0 ) {
        Log(LOG_WARNING, "Failed to open pidfile '%s': %s", pidfile,
                strerror(errno));
        return -1;
    }

    /*
     * Try to get a lock on the pidfile. If something else has it locked then
     * that probably means we are already running.
     */
    if ( lockf(fd, F_TLOCK, 0) < 0 ) {
        if ( errno == EACCES || errno == EAGAIN ) {
            Log(LOG_WARNING, "pidfile '%s' locked, is it already running?",
                    pidfile);
        } else {
            Log(LOG_WARNING, "Failed to lock pidfile '%s': %s", pidfile,
                    strerror(errno));
        }
        close(fd);
        return -1;
    }

    /* Empty the file, we are going to replace whatever was in it */
    if ( ftruncate(fd, 0) < 0 ) {
        Log(LOG_WARNING, "Failed to truncate pidfile '%s': %s", pidfile,
                strerror(errno));
        close(fd);
        return -1;
    }

    snprintf(buf, sizeof(buf) - 1, "%d\n", getpid());
    buf[sizeof(buf) - 1] = '\0';

    if ( write(fd, buf, strlen(buf)) < 0 ) {
        Log(LOG_WARNING, "Failed to write to pidfile '%s': %s", pidfile,
                strerror(errno));
        close(fd);
        return -1;
    }

    return 0;
}



/*
 * Set the flag that will cause libwandevent to stop running the main event
 * loop and return control to us.
 */
static void stop_running(wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data) {

    Log(LOG_DEBUG, "Received signal, exiting event loop");
    ev_hdl->running = false;
}



/*
 * If measured gets sent a SIGHUP or SIGUSR1 then it should reload all the
 * available test modules and re-read the schedule file taking into account
 * the new list of available tests.
 */
static void reload(wand_event_handler_t *ev_hdl, int signum, void *data) {
    char nametable[PATH_MAX];
    char schedule[PATH_MAX];
    amp_test_meta_t *meta = (amp_test_meta_t*)data;

    /* signal > 0 is a real signal meaning "reload", signal == 0 is "load" */
    if ( signum > 0 ) {
        Log(LOG_INFO, "Received signal %d, reloading all configuration",signum);

        /* cancel all scheduled tests (let running ones finish) */
        clear_test_schedule(ev_hdl, 0);

        /* empty the nametable */
        clear_nametable();

        /* unload all the test modules */
        unregister_tests();
    }

    /* load all test modules again, they may have changed */
    if ( register_tests(AMP_TEST_DIRECTORY) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	exit(1);
    }

    /* re-read nametable files from the global and client specific dirs */
    read_nametable_dir(NAMETABLE_DIR);
    snprintf((char*)&nametable, PATH_MAX, "%s/%s", NAMETABLE_DIR,meta->ampname);
    read_nametable_dir(nametable);

    /* re-read schedule files from the global and client specific dirs */
    read_schedule_dir(ev_hdl, SCHEDULE_DIR, meta);
    snprintf((char*)&schedule, PATH_MAX, "%s/%s", SCHEDULE_DIR, meta->ampname);
    read_schedule_dir(ev_hdl, schedule, meta);
}



/*
 * Loading everything for the first time is almost the same as reloading all
 * the configuration after receiving a signal, just call through to reload().
 */
static void load_tests_and_schedules(wand_event_handler_t *ev_hdl,
        amp_test_meta_t *meta) {
    reload(ev_hdl, 0, meta);
}



/*
 * Dump internal scheduling information to a file for later analysis. We need
 * to be able to see the current state of the schedule to diagnose scheduling
 * problems and it's not always possible to run in full debug mode (lots of
 * output!).
 */
static void debug_dump(wand_event_handler_t *ev_hdl, int signum,
        __attribute__((unused))void *data) {

    char *filename;
    FILE *out;

    if ( asprintf(&filename, "%s.%d", DEBUG_SCHEDULE_DUMP_FILE,getpid()) < 0 ) {
        Log(LOG_WARNING, "Failed to build filename for debug schedule output");
        return;
    }

    Log(LOG_INFO, "Received signal %d, dumping debug information to '%s'",
            signum, filename);

    if ( (out = fopen(filename, "a")) == NULL ) {
        Log(LOG_WARNING, "Failed to open debug schedule output file '%s': %s",
                filename, strerror(errno));
        return;
    }

    dump_schedule(ev_hdl, out);

    fclose(out);
    free(filename);
}



/*
 *
 */
static void free_local_meta_vars(amp_test_meta_t *meta) {
    if ( meta == NULL ) {
        Log(LOG_WARNING, "Attempting to free NULL test meta variables");
        return;
    }

    if ( meta->interface ) free(meta->interface);
    if ( meta->sourcev4 ) free(meta->sourcev4);
    if ( meta->sourcev6 ) free(meta->sourcev6);
    /* meta->ampname is a pointer to the global variable, leave it */;
}



/*
 *
 */
static void free_global_vars(struct amp_global_t *vars) {
    if ( vars == NULL ) {
        Log(LOG_WARNING, "Attempting to free NULL global variables");
        return;
    }

    if ( vars->ampname ) free(vars->ampname);
    if ( vars->local ) free(vars->local);
    if ( vars->collector ) free(vars->collector);
    if ( vars->vhost ) free(vars->vhost);
    if ( vars->exchange ) free(vars->exchange);
    if ( vars->routingkey ) free(vars->routingkey);
    if ( vars->amqp_ssl.keys_dir ) free(vars->amqp_ssl.keys_dir);
    if ( vars->amqp_ssl.cacert ) free(vars->amqp_ssl.cacert);
    if ( vars->amqp_ssl.cert ) free(vars->amqp_ssl.cert);
    if ( vars->amqp_ssl.key ) free(vars->amqp_ssl.key);
    if ( vars->asnsock ) free(vars->asnsock);
    if ( vars->nssock ) free(vars->nssock);
}



/*
 *
 */
int main(int argc, char *argv[]) {
    wand_event_handler_t *ev_hdl;
    char *config_file = NULL;
    char *pidfile = NULL;
    int fetch_remote = 1;
    int backgrounded = 0;
    struct amp_asn_info *asn_info;
    amp_test_meta_t meta;
    amp_control_t *control;
    fetch_schedule_item_t *fetch;
    cfg_t *cfg;
    int opt;

    memset(&meta, 0, sizeof(meta));
    meta.inter_packet_delay = MIN_INTER_PACKET_DELAY;

    while ( (opt = getopt_long(argc, argv, "dhp:vxc:rZ:I:4:6:",
                    long_options, NULL)) != -1 ) {

	switch ( opt ) {
	    case 'd':
		/* daemonise, detach, close stdin/out/err, etc */
		if ( daemon(0, 0) < 0 ) {
		    perror("daemon");
		    return -1;
		}
                backgrounded = 1;
		break;
	    case 'v':
		/* print version and build info */
                print_measured_version(argv[0]);
                exit(0);
	    case 'x':
		/* enable extra debug output, overriding config settings */
                /* TODO allow the exact log level to be set? */
		log_level = LOG_DEBUG;
                log_level_override = 1;
		break;
	    case 'c':
		/* specify a configuration file */
		config_file = optarg;
		break;
            case 'p':
                pidfile = optarg;
                break;
            case 'r':
                /* override config settings and don't fetch remote schedules */
                fetch_remote = 0;
                break;
            case 'I':
                /* override config settings and set the source interface */
                meta.interface = optarg;
                break;
            case 'Z':
                /* override config settings and set the interpacket delay */
                meta.inter_packet_delay = atoi(optarg);
                break;
            case '4':
                /* override config settings and set the source IPv4 address */
                meta.sourcev4 = optarg;
                break;
            case '6':
                /* override config settings and set the source IPv6 address */
                meta.sourcev6 = optarg;
                break;
	    case 'h':
	    default:
		usage();
		exit(0);
	};
    }

    /* save the pointer to argv so that we can overwrite the name later */
    vars.argc = argc;
    vars.argv = argv;

    /*
     * Reset optind so the tests can call getopt normally on it's arguments.
     * We reset it to 0 rather than 1 because we mess with argv when calling
     * the tests and getopt needs to be completely reinitialised to work.
     */
    optind = 0;

#if LOG_TO_SYSLOG
    /*
     * We are going to mess with argv later, which can mess with process
     * identfication. Lets force it to always be named after the package.
     */
    openlog(PACKAGE, LOG_PID, LOG_USER);
#endif

    Log(LOG_INFO, "%s starting", PACKAGE_STRING);

    /* load the default config file if one isn't specified */
    if ( !config_file ) {
	config_file = AMP_CLIENT_CONFIG_DIR "/default.conf";
    }

    /*
     * Parse the config file and set all the variables that we know we will
     * use. The rest will wait until we need them.
     */
    if ( (cfg = parse_config(config_file, &vars)) == NULL ) {
	return -1;
    }

    /* use the configured log level if it isn't set on the command line */
    if ( !log_level_override ) {
        log_level = get_loglevel_config(cfg);
    }

    /*
     * TODO do we always want to create the pidfile, or only when daemonised?
     * or only when explicitly set?
     * TODO is this the best location to create the pidfile? After parsing
     * configuration so we can log at the right level, but before doing any
     * real work -- especially important that it is before checking SSL keys
     * and certs, which can block waiting on them to be signed.
     */
    if ( pidfile && create_pidfile(pidfile) < 0 ) {
        Log(LOG_WARNING, "Failed to create pidfile %s, aborting", pidfile);
        cfg_free(cfg);
        return -1;
    }

    /* update the iface structure with any interface config from config file */
    get_interface_config(cfg, &meta);
    meta.ampname = vars.ampname;

    /* set up the dns resolver context */
    if ( (vars.ctx = get_dns_context_config(cfg, &meta)) == NULL ) {
        Log(LOG_ALERT, "Failed to configure resolver, aborting.");
	cfg_free(cfg);
        return -1;
    }

    /* determine the directory that the ssl keys should be stored in */
    if ( asprintf(&vars.amqp_ssl.keys_dir, "%s/%s", AMP_KEYS_DIR,
                vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build custom keys directory path");
	cfg_free(cfg);
        return -1;
    }

    /*
     * Prevent rabbitmq-c from initialising SSL on the first call to
     * amqp_open_socket() - we set up the SSL context with limited ciphers and
     * options to enforce peer verification etc and want to make sure that it
     * gets used by everything.
     */
    amqp_set_initialize_ssl_library(0);

    /*
     * Set up SSL certificates etc. This has to go before curl_global_init()
     * because if we fail then we clean up a whole lot of openssl stuff.
     * Also needs to go before the rabbit shovel configuration, as the certs
     * and keys are required to set that up too.
     * TODO determine which bits we can clean up and which bits we can't.
     */
    if ( initialise_ssl(&vars.amqp_ssl, vars.collector) < 0 ) {
        Log(LOG_WARNING, "Failed to initialise SSL, aborting");
	cfg_free(cfg);
        return -1;
    }

    /* set up curl while we are still the only measured process running */
    curl_global_init(CURL_GLOBAL_ALL);

    /*
     * Make sure certs are valid and loaded. Do not proceed if there are any
     * problems with this.
     */
    if ( (get_certificate(&vars.amqp_ssl, vars.ampname,
                    vars.collector, should_wait_for_cert(cfg)) != 0 ||
                (ssl_ctx = initialise_ssl_context(&vars.amqp_ssl)) == NULL) ) {
        Log(LOG_ALERT, "Failed to load SSL keys/certificates, aborting");
	cfg_free(cfg);
        return -1;
    }

    /*
     * Try to configure the local rabbitmq broker. The easiest way to deal
     * with this at the moment is to check every time we run - this could be
     * a new client. The old approach was to run this manually, but that
     * falls over somewhat if certificate fetching is going on (we need the
     * certs now, and exiting after configuring rabbit isn't helpful).
     * XXX rethink this again? is it worth having a standalone program that
     * can read the config file just to do this?
     */
    if ( should_config_rabbit(cfg) ) {
        Log(LOG_DEBUG, "Configuring rabbitmq for amplet2 client %s",
                vars.ampname);
        /*
         * If we are using a local broker to give more resiliency then
         * we should make our own user and vhost, give ourselves a private
         * space to operate within.
         */
        if ( setup_rabbitmq_user(vars.ampname) < 0 ) {
            Log(LOG_ALERT, "Failed to create user, aborting");
            cfg_free(cfg);
            return -1;
        }

        /*
         * The shovel is used to send data from our local queues to the
         * remote collector via an SSL secured connection.
         */
        if ( setup_rabbitmq_shovel(vars.ampname, vars.local, vars.collector,
                    vars.port, vars.amqp_ssl.cacert, vars.amqp_ssl.cert,
                    vars.amqp_ssl.key, vars.exchange, vars.routingkey) < 0 ) {
            Log(LOG_ALERT, "Failed to create shovel, aborting");
            cfg_free(cfg);
            return -1;
        }
        Log(LOG_DEBUG, "Done configuring rabbitmq");
    } else {
        /*
         * If we aren't using a local broker then there is no configuration
         * to perform - we are reporting directly to a remote broker that
         * we can't really configure from here.
         */
        Log(LOG_DEBUG, "vialocal = false, no local configuration");
    }

    /* set up event handlers */
    wand_event_init();
    ev_hdl = wand_create_event_handler();
    assert(ev_hdl);

    /* construct our custom, per-client nameserver socket */
    if ( asprintf(&vars.nssock, "%s/%s.sock", AMP_RUN_DIR, vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build local resolve socket path");
	cfg_free(cfg);
        return -1;
    }

    /* construct our custom, per-client asn lookup socket */
    if ( asprintf(&vars.asnsock, "%s/%s.asn", AMP_RUN_DIR, vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build local asn socket path");
	cfg_free(cfg);
        return -1;
    }

    /* if remote fetching is enabled, try to get the config for it */
    if ( fetch_remote && (fetch = get_remote_schedule_config(cfg)) ) {
        /* TODO fetch gets leaked, has lots of parts needing to be freed */
        if ( enable_remote_schedule_fetch(ev_hdl, fetch) < 0 ) {
            Log(LOG_ALERT, "Failed to enable remote schedule fetching");
            cfg_free(cfg);
            return -1;
        }

        /* SIGUSR2 should trigger a refetch of any remote schedule files */
        wand_add_signal(SIGUSR2, fetch, signal_fetch_callback);
    } else {
        /* if fetching isn't enabled then just reload the current schedule */
        wand_add_signal(SIGUSR2, &meta, reload);
    }

    /* set up a handler to deal with SIGINT/SIGTERM so we can shutdown nicely */
    wand_add_signal(SIGINT, NULL, stop_running);
    wand_add_signal(SIGTERM, NULL, stop_running);

    /* set up handler to deal with SIGCHLD so we can tidy up after tests */
    wand_add_signal(SIGCHLD, NULL, child_reaper);

    /* create the resolver/cache unix socket and add event listener for it */
    if ( (vars.nssock_fd = initialise_local_socket(vars.nssock)) < 0 ) {
        Log(LOG_ALERT, "Failed to initialise local resolver, aborting");
	cfg_free(cfg);
        return -1;
    }
    wand_add_fd(ev_hdl, vars.nssock_fd, EV_READ, vars.ctx,
            resolver_socket_event_callback);

    /* create the asn lookup unix socket and add event listener for it */
    Log(LOG_DEBUG, "Creating local socket for ASN lookups");
    if ( (vars.asnsock_fd = initialise_local_socket(vars.asnsock)) < 0 ) {
        Log(LOG_ALERT, "Failed to initialise local asn resolver, aborting");
	cfg_free(cfg);
        return -1;
    }

    asn_info = initialise_asn_info();
    //XXX can we move this and socket creation off into the function too?
    wand_add_fd(ev_hdl, vars.asnsock_fd, EV_READ, asn_info,
            asn_socket_event_callback);

    /* save the port, tests need to know where to connect */
    control = get_control_config(cfg, &meta);

    /* TODO what is the best way to get this port to the tests that need it? */
    vars.control_port = atol(control->port); /* XXX */
    //meta.control_port = atol(control->port); /* XXX */

    /* if SSL is properly enabled then try to create the control sockets */
    if ( ssl_ctx != NULL && control->enabled ) {
        if ( initialise_control_socket(ev_hdl, control) < 0 ) {
            Log(LOG_WARNING, "Failed to start control socket!");
        }
    } else if ( ssl_ctx != NULL ) {
        Log(LOG_DEBUG, "Control socket is disabled, skipping");
    }

    /* configuration is done, free the object */
    cfg_free(cfg);

    /*
     * Set up handler to deal with SIGHUP to reload available tests if running
     * without a TTY. With a TTY we want SIGHUP to terminate measured.
     */
    if ( backgrounded ) {
        wand_add_signal(SIGHUP, &meta, reload);
    }

    /* SIGUSR1 should also reload tests/schedules, we use this internally */
    wand_add_signal(SIGUSR1, &meta, reload);

    /* SIGRTMAX is a debug signal to dump internal state */
    wand_add_signal(SIGRTMAX, NULL, debug_dump);

    /* register all test modules, load nametable, load schedules */
    load_tests_and_schedules(ev_hdl, &meta);

    /* give up control to libwandevent */
    wand_event_run(ev_hdl);


    Log(LOG_INFO, "Shutting down");

    /* if we get control back then it's time to tidy up */
    Log(LOG_DEBUG, "Clearing test schedules");
    clear_test_schedule(ev_hdl, 1);

    Log(LOG_DEBUG, "Clearing name table");
    clear_nametable();

    /* destroying event handler will also clear all signal handlers etc */
    Log(LOG_DEBUG, "Clearing event handlers");
    wand_destroy_event_handler(ev_hdl);

    //TODO shutdown control socket?
    free_control_config(control);

    free_local_meta_vars(&meta);
    free_global_vars(&vars);

    /* clean up the ASN socket, mutex, storage */
    Log(LOG_DEBUG, "Shutting down ASN lookup");
    close(vars.asnsock_fd);
    amp_asn_info_delete(asn_info);

    Log(LOG_DEBUG, "Shutting down DNS resolver");
    close(vars.nssock_fd);
    amp_resolver_context_delete(vars.ctx);

    Log(LOG_DEBUG, "Cleaning up SSL");
    ssl_cleanup();

    /* finish up with curl */
    /* TODO what if we are in the middle of updating remote schedule files? */
    Log(LOG_DEBUG, "Cleaning up curl");
    curl_global_cleanup();

    /* clear out all the test modules that were registered */
    unregister_tests();

    /* remove the pidfile if one was created */
    if ( pidfile ) {
        if ( unlink(pidfile) < 0 ) {
            Log(LOG_WARNING, "Failed to remove pidfile '%s': %s", pidfile,
                    strerror(errno));
        }
    }

    Log(LOG_DEBUG, "Shutdown complete");

    return 0;
}
