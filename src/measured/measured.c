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
#include <event2/event.h>
#include <confuse.h>
#include <limits.h>
#include <time.h>

#if _WIN32
#include <event2/thread.h>
#include "w32-compat.h"
#include "w32-service.h"
#endif

#include "config.h"
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
#include "users.h"
#include "clock.h"

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
    {"pidfile", required_argument, 0, 'p'},
    {"rundir", required_argument, 0, 'n'},
    {0, 0, 0, 0}
};



/*
 * Print a simple usage statement showing how to run the program.
 */
static void usage(void) {

    fprintf(stderr, "Usage: amplet2 [-dvxr] [-c <config>] [-I <iface>]\n"
            "               [-4 [<address>]] [-6 [<address>]]\n");
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
#ifndef _WIN32
static int create_pidfile(char *pidfile) {
    int fd;
    char buf[128] = {0};
    int flags = O_RDWR | O_CREAT;

    assert(pidfile);

    Log(LOG_DEBUG, "Creating pidfile '%s'", pidfile);

    /*
     * Open pid file (creating if needed) and set to close on exec. Don't
     * truncate it or anything similar, as we don't want to touch it until
     * after we have got a lock on it.
     */
#if _WIN32
    flags |= _O_NOINHERIT;
#else
    flags |= O_CLOEXEC;
#endif

    if ( (fd = open(pidfile, flags, S_IRUSR | S_IWUSR)) < 0 ) {
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

    if ( write(fd, buf, strlen(buf)) < 0 ) {
        Log(LOG_WARNING, "Failed to write to pidfile '%s': %s", pidfile,
                strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}
#endif



/*
 * Call the method that will cause libevent to stop running the main event
 * loop and return control to us.
 */
static void stop_running(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void *evdata) {

    struct event_base *base = (struct event_base *)evdata;
    Log(LOG_DEBUG, "Received signal, exiting event loop");
    event_base_loopbreak(base);
}



/*
 * If measured gets sent a SIGHUP or SIGUSR1 then it should reload all the
 * available test modules and re-read the schedule file taking into account
 * the new list of available tests.
 */
static void reload(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void *evdata) {
    char schedule[PATH_MAX];
    amp_test_meta_t *meta = (amp_test_meta_t*)evdata;

    /* signal > 0 is a real signal meaning "reload", signal == 0 is "load" */
    if ( evsock > 0 ) {
        Log(LOG_INFO, "Received signal %d, reloading all configuration",evsock);

        /* cancel all scheduled tests (let running ones finish) */
        clear_test_schedule(meta->base, 0);

        /* unload all the test modules */
        unregister_tests();
    }

    /* load all test modules again, they may have changed */
    if ( register_tests(AMP_TEST_DIRECTORY) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	exit(EXIT_FAILURE);
    }

    /* re-read schedule files from the global and client specific dirs */
    read_schedule_dir(meta->base, SCHEDULE_DIR, meta);
    snprintf((char*)&schedule, PATH_MAX, "%s/%s", SCHEDULE_DIR, meta->ampname);
    read_schedule_dir(meta->base, schedule, meta);
}



/*
 * Loading everything for the first time is almost the same as reloading all
 * the configuration after receiving a signal, just call through to reload().
 */
static void load_tests_and_schedules(amp_test_meta_t *meta) {
    reload(0, 0, meta);
}



#ifndef _WIN32
/*
 * Dump internal scheduling information to a file for later analysis. We need
 * to be able to see the current state of the schedule to diagnose scheduling
 * problems and it's not always possible to run in full debug mode (lots of
 * output!).
 */
static void debug_dump(evutil_socket_t evsock,
        __attribute__((unused))short flags, void *evdata) {

    char *filename;
    FILE *out;
    struct event_base *base = evdata;

    if ( asprintf(&filename, "%s.%d", DEBUG_SCHEDULE_DUMP_FILE,getpid()) < 0 ) {
        Log(LOG_WARNING, "Failed to build filename for debug schedule output");
        return;
    }

    Log(LOG_INFO, "Received signal %d, dumping debug information to '%s'",
            evsock, filename);

    if ( (out = fopen(filename, "a")) == NULL ) {
        Log(LOG_WARNING, "Failed to open debug schedule output file '%s': %s",
                filename, strerror(errno));
        return;
    }

    dump_schedule(base, out);

    fclose(out);
    free(filename);
}
#endif



/*
 * Free the memory allocated for the meta interface variables.
 */
static void free_local_meta_vars(amp_test_meta_t *meta) {
    if ( meta == NULL ) {
        Log(LOG_WARNING, "Attempting to free NULL test meta variables");
        return;
    }

    if ( meta->iface ) free(meta->iface);
    if ( meta->sourcev4 ) free(meta->sourcev4);
    if ( meta->sourcev6 ) free(meta->sourcev6);
    /* meta->ampname is a pointer to the global variable, leave it */;
}



/*
 * Free the memory allocated for the global variable.
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



#if _WIN32
int main(int argc, char *argv[]) {
    SERVICE_TABLE_ENTRY servicetable[] = {
        {AMP_SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
        {NULL,NULL}
    };

    /* hand over to the service main function if running as a service */
    if ( !StartServiceCtrlDispatcher(servicetable) ) {
        int error = GetLastError();
        if ( error != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT ) {
            Log(LOG_WARNING, "Could not start service! (%s)\n", sockerr(error));
            return -1;
        }

        /* otherwise run it standalone */
        Log(LOG_DEBUG, "Running standalone, not as a service");
        actual_main(argc, argv);
    }
}



int actual_main(int argc, char *argv[]) {
#else
int main(int argc, char *argv[]) {
    struct event *signal_usr1 = NULL;
    int backgrounded = 0;
    char *rundir = AMP_RUN_DIR;
#endif
    char *config_file = NULL;
    char *pidfile = NULL;
    int fetch_remote = 1;
    struct amp_asn_info *asn_info;
    amp_test_meta_t meta;
    amp_control_t *control;
    fetch_schedule_item_t *fetch;
    cfg_t *cfg;
    int opt;
    char *address_string;
    struct event *signal_load = NULL;
    struct event *signal_int = NULL;
    struct event *signal_term = NULL;
    struct event *signal_chld = NULL;
    struct event *resolver_socket_event = NULL;
    struct event *asn_socket_event = NULL;
    struct event *signal_hup = NULL;
    struct event *signal_tmax = NULL;
    struct ub_ctx *dns_ctx;
    char nametable[PATH_MAX];
    char *username = NULL;

#if _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", err);
        exit(EXIT_FAILURE);
    }
#endif

    memset(&meta, 0, sizeof(meta));
    meta.inter_packet_delay = MIN_INTER_PACKET_DELAY;

    while ( (opt = getopt_long(argc, argv, "dhn:p:vxc:rZ:I:4::6::",
                    long_options, NULL)) != -1 ) {

        switch ( opt ) {
            case 'd':
#if _WIN32
                assert(0);
#else
                /* daemonise, detach, close stdin/out/err, etc */
                if ( daemon(0, 0) < 0 ) {
                    perror("daemon");
                    exit(EXIT_FAILURE);
                }
                backgrounded = 1;
#endif
                break;
            case 'v':
                /* print version and build info */
                print_measured_version(argv[0]);
                exit(EXIT_SUCCESS);
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
            case 'n':
                rundir = optarg;
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
                meta.iface = optarg;
                break;
            case 'Z':
                /* override config settings and set the interpacket delay */
                meta.inter_packet_delay = atoi(optarg);
                break;
            case '4':
                /* override config settings and set the source IPv4 address */
                address_string = parse_optional_argument(argv);
                if ( address_string ) {
                    meta.sourcev4 = optarg;
                } else {
                    meta.sourcev4 = "any";
                }
                break;
            case '6':
                /* override config settings and set the source IPv6 address */
                address_string = parse_optional_argument(argv);
                if ( address_string ) {
                    meta.sourcev6 = optarg;
                } else {
                    meta.sourcev6 = "any";
                }
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            default:
                usage();
                exit(EXIT_FAILURE);
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

    srandom(time(NULL));

    /* load the default config file if one isn't specified */
    if ( !config_file ) {
	config_file = AMP_CLIENT_CONFIG_DIR "/default.conf";
    }

    /*
     * Parse the config file and set all the variables that we know we will
     * use. The rest will wait until we need them.
     */
    if ( (cfg = parse_config(config_file, &vars)) == NULL ) {
	exit(EXIT_FAILURE);
    }

    /* use the configured log level if it isn't set on the command line */
    if ( !log_level_override ) {
        log_level = get_loglevel_config(cfg);
    }

#ifndef _WIN32
    /*
     * Create rundir before pidfiles are written or local sockets
     * are configured. They both expect rundir to exist, and it may
     * not if the run directory is mounted on a tmpfs.
     */
    username = get_change_user_config(cfg);
    if ( mkdir_and_chown(username, rundir, 0755) != 0 ) {
        Log(LOG_WARNING, "Failed to create run directory, aborting");
        exit(EXIT_FAILURE);
    }

    /*
     * TODO is this the best location to create the pidfile? After parsing
     * configuration so we can log at the right level, but before doing any
     * real work -- especially important that it is before checking SSL keys
     * and certs, which can block waiting on them to be signed.
     */
    if ( pidfile && create_pidfile(pidfile) < 0 ) {
        Log(LOG_WARNING, "Failed to create pidfile %s, aborting", pidfile);
        cfg_free(cfg);
        exit(EXIT_FAILURE);
    }
#endif

    /* update the iface structure with any interface config from config file */
    get_interface_config(cfg, &meta);
    meta.ampname = vars.ampname;

    /* set up the dns resolver context */
    if ( (dns_ctx = get_dns_context_config(cfg, &meta)) == NULL ) {
        Log(LOG_ALERT, "Failed to configure resolver, aborting.");
	cfg_free(cfg);
        exit(EXIT_FAILURE);
    }

    /* determine the directory that the ssl keys should be stored in */
    if ( asprintf(&vars.amqp_ssl.keys_dir, "%s/%s", AMP_KEYS_DIR,
                vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build custom keys directory path");
	cfg_free(cfg);
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }

    /* set up curl while we are still the only measured process running */
    curl_global_init(CURL_GLOBAL_ALL);

#ifndef _WIN32
    if ( should_wait_for_clock_sync(cfg) ) {
        Log(LOG_DEBUG, "Waiting for clock synchronisation");
        wait_for_clock_sync();
        Log(LOG_DEBUG, "Got clock synchronisation");
    }
#endif

    /*
     * Make sure certs are valid and loaded. Do not proceed if there are any
     * problems with this.
     */
    if ( (get_certificate(&vars.amqp_ssl, vars.ampname,
                    vars.collector, should_wait_for_cert(cfg)) != 0 ||
                (ssl_ctx = initialise_ssl_context(&vars.amqp_ssl)) == NULL) ) {
        Log(LOG_ALERT, "Failed to load SSL keys/certificates, aborting");
	cfg_free(cfg);
        exit(EXIT_FAILURE);
    }

#ifndef _WIN32
    /*
     * Try to configure the local rabbitmq broker. The easiest way to deal
     * with this at the moment is to check every time we run - this could be
     * a new client. The old approach was to run this manually, but that
     * falls over somewhat if certificate fetching is going on (we need the
     * certs now, and exiting after configuring rabbit isn't helpful).
     * XXX rethink this again? is it worth having a standalone program that
     * can read the config file just to do this?
     * XXX running rabbitmqctl is the only reason that amplet2 needs to run
     * as root, can we avoid it by using the HTTP management interface?
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
            exit(EXIT_FAILURE);
        }

        /*
         * The shovel is used to send data from our local queues to the
         * remote collector via an SSL secured connection.
         */
        if ( setup_rabbitmq_shovel(vars.ampname, vars.local, vars.collector,
                    vars.port, vars.amqp_ssl.cacert, vars.amqp_ssl.cert,
                    vars.amqp_ssl.key, vars.exchange, vars.routingkey,
                    vars.prefetch) < 0 ) {
            Log(LOG_ALERT, "Failed to create shovel, aborting");
            cfg_free(cfg);
            exit(EXIT_FAILURE);
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

    /* drop root permissions now that we no longer need them to set up rabbit */
    if ( username ) {
        if ( change_user(username) < 0 ) {
            Log(LOG_ALERT, "Failed to change to user '%s', aborting", username);
            cfg_free(cfg);
            exit(EXIT_FAILURE);
        }
    }
#endif

#if _WIN32
    /* we want to manually generate events from multiple threads */
    if ( evthread_use_windows_threads() < 0 ) {
        Log(LOG_WARNING, "Failed to initialise libevent threading");
        exit(EXIT_FAILURE);
    }
#endif

    /*
     * stop libevent using epoll due to the way it handles signals in only
     * one event_base at a time. Resetting it after forking appears to fix
     * the behaviour, but still triggers scary looking warning messages.
     */
#ifndef _WIN32
    const char *event_noepoll = "1";
    if ( setenv("EVENT_NOEPOLL", event_noepoll, 0) < 0 ) {
        Log(LOG_WARNING, "Failed to disable libevent epoll");
        cfg_free(cfg);
        exit(EXIT_FAILURE);
    }
#endif

    /* set up event handlers */
    meta.base = event_base_new();
    assert(meta.base);

#if _WIN32
    // TODO figure out what ports to use
    vars.nssock = strdup("6653");
    vars.asnsock = strdup("6654");
#else
    /* construct our custom, per-client nameserver socket */
    if ( asprintf(&vars.nssock, "%s/%s.sock", rundir, vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build local resolve socket path");
	cfg_free(cfg);
        exit(EXIT_FAILURE);
    }

    /* construct our custom, per-client asn lookup socket */
    if ( asprintf(&vars.asnsock, "%s/%s.asn", rundir, vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build local asn socket path");
	cfg_free(cfg);
        exit(EXIT_FAILURE);
    }
#endif

    /* if remote fetching is enabled, try to get the config for it */
    if ( fetch_remote && (fetch = get_remote_schedule_config(cfg)) ) {
        /* TODO fetch gets leaked, has lots of parts needing to be freed */
        if ( enable_remote_schedule_fetch(meta.base, fetch) < 0 ) {
            Log(LOG_ALERT, "Failed to enable remote schedule fetching");
            cfg_free(cfg);
            exit(EXIT_FAILURE);
        }

#ifndef _WIN32
        /* SIGUSR2 should trigger a refetch of any remote schedule files */
        signal_load = event_new(meta.base, SIGUSR2,
                EV_SIGNAL|EV_PERSIST, signal_fetch_callback, fetch);
        event_add(signal_load, NULL);
#endif
    } else {
#ifndef _WIN32
        /* if fetching isn't enabled then just reload the current schedule */
        signal_load = event_new(meta.base, SIGUSR2,
                EV_SIGNAL|EV_PERSIST, reload, &meta);
        event_add(signal_load, NULL);
#endif
    }

    /* set up a handler to deal with SIGINT/SIGTERM so we can shutdown nicely */
    signal_int = event_new(meta.base, SIGINT,
            EV_SIGNAL|EV_PERSIST, stop_running, meta.base);
    event_add(signal_int, NULL);
    signal_term = event_new(meta.base, SIGTERM,
            EV_SIGNAL|EV_PERSIST, stop_running, meta.base);
    event_add(signal_term, NULL);

#ifndef _WIN32
    /* set up handler to deal with SIGCHLD so we can tidy up after tests */
    signal_chld = event_new(meta.base, SIGCHLD,
            EV_SIGNAL|EV_PERSIST, child_reaper, NULL);
    event_add(signal_chld, NULL);
#endif

    /* create the resolver/cache unix socket and add event listener for it */
    if ( (vars.nssock_fd = initialise_local_socket(vars.nssock)) < 0 ) {
        Log(LOG_ALERT, "Failed to initialise local resolver, aborting");
        cfg_free(cfg);
        exit(EXIT_FAILURE);
    }
    resolver_socket_event = event_new(meta.base, vars.nssock_fd,
            EV_READ|EV_PERSIST, resolver_socket_event_callback, dns_ctx);
    event_add(resolver_socket_event, NULL);

    /* create the asn lookup unix socket and add event listener for it */
    Log(LOG_DEBUG, "Creating local socket for ASN lookups");
    if ( (vars.asnsock_fd = initialise_local_socket(vars.asnsock)) < 0 ) {
        Log(LOG_ALERT, "Failed to initialise local asn resolver, aborting");
	cfg_free(cfg);
        exit(EXIT_FAILURE);
    }

    asn_info = initialise_asn_info();
    //XXX can we move this and socket creation off into the function too?
    asn_socket_event = event_new(meta.base, vars.asnsock_fd,
            EV_READ|EV_PERSIST, asn_socket_event_callback, asn_info);
    event_add(asn_socket_event, NULL);

    /* save the port, tests need to know where to connect */
    control = get_control_config(cfg, &meta);

    /* TODO what is the best way to get this port to the tests that need it? */
    vars.control_port = atol(control->port); /* XXX */

    /* if SSL is properly enabled then try to create the control sockets */
    if ( ssl_ctx != NULL && control->enabled ) {
        if ( initialise_control_socket(meta.base, control) < 0 ) {
            Log(LOG_WARNING, "Failed to start control socket!");
        }
    } else if ( ssl_ctx != NULL ) {
        Log(LOG_DEBUG, "Control socket is disabled, skipping");
    }

    /* load the nametable files into unbound */
    read_nametable_dir(dns_ctx, NAMETABLE_DIR);
    snprintf((char*)&nametable, PATH_MAX, "%s/%s", NAMETABLE_DIR, meta.ampname);
    read_nametable_dir(dns_ctx, nametable);

    /* register all test modules, load schedules */
    load_tests_and_schedules(&meta);

    /* get the default arguments that should be applied to each test */
    get_default_test_args(cfg);

    /* configuration is done, free the object */
    cfg_free(cfg);

#ifdef _WIN32
    /* create but don't add this event so that it can be triggered manually */
    signal_usr1 = event_new(meta.base, SIGUSR1, 0, reload, &meta);
#else
    /*
     * Set up handler to deal with SIGHUP to reload available tests if running
     * without a TTY. With a TTY we want SIGHUP to terminate measured.
     */
    if ( backgrounded ) {
        signal_hup = event_new(meta.base, SIGHUP,
                EV_SIGNAL|EV_PERSIST, reload, &meta);
        event_add(signal_hup, NULL);
    }

    /* SIGUSR1 should also reload tests/schedules, we use this internally */
    signal_usr1 = event_new(meta.base, SIGUSR1,
            EV_SIGNAL|EV_PERSIST, reload, &meta);
    event_add(signal_usr1, NULL);

    /* SIGRTMAX is a debug signal to dump internal state */
    signal_tmax = event_new(meta.base, SIGRTMAX,
            EV_SIGNAL|EV_PERSIST, debug_dump, meta.base);
    event_add(signal_tmax, NULL);
#endif

    /* give up control to libevent */
    event_base_dispatch(meta.base);


    Log(LOG_INFO, "Shutting down");

    /* if we get control back then it's time to tidy up */
    Log(LOG_DEBUG, "Clearing test schedules");
    clear_test_schedule(meta.base, 1);

    Log(LOG_DEBUG, "Clearing name table");
    clear_nametable();

    Log(LOG_DEBUG, "Stopping control socket");
    free_control_config(control);

    /* clean up all the signal handlers */
    Log(LOG_DEBUG, "Clearing event handlers");
    if ( signal_load ) event_free(signal_load);
    if ( signal_int ) event_free(signal_int);
    if ( signal_term ) event_free(signal_term);
    if ( signal_chld ) event_free(signal_chld);
    if ( resolver_socket_event ) event_free(resolver_socket_event);
    if ( asn_socket_event ) event_free(asn_socket_event);
    if ( signal_hup ) event_free(signal_hup);
    if ( signal_usr1 ) event_free(signal_usr1);
    if ( signal_tmax ) event_free(signal_tmax);

    Log(LOG_DEBUG, "Clearing libevent");
    event_base_free(meta.base);

    free_local_meta_vars(&meta);
    free_global_vars(&vars);

    /* clean up the ASN socket, mutex, storage */
    Log(LOG_DEBUG, "Shutting down ASN lookup");
    close(vars.asnsock_fd);
    amp_asn_info_delete(asn_info);

    Log(LOG_DEBUG, "Shutting down DNS resolver");
    close(vars.nssock_fd);
    amp_resolver_context_delete(dns_ctx);

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

#if _WIN32
    WSACleanup();
#endif

    Log(LOG_DEBUG, "Shutdown complete");

    return EXIT_SUCCESS;
}
