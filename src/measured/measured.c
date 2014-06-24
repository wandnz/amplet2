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
#include <confuse.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <curl/curl.h>
#include <libwandevent.h>
#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "nametable.h"
#include "debug.h"
#include "messaging.h"
#include "modules.h"
#include "global.h"
#include "control.h"
#include "ssl.h"
#include "ampresolv.h"
#include "testlib.h"
#include "rabbitcfg.h"
#include "nssock.h"

#define AMP_CLIENT_CONFIG_DIR AMP_CONFIG_DIR "/clients"

wand_event_handler_t *ev_hdl;

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
    {"setup-rabbitmq", no_argument, 0, 'f'},
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
    fprintf(stderr, "  -f, --setup-rabbitmq      Configure rabbitmq based on AMP config and exit\n");
    fprintf(stderr, "  -d, --daemonise           Detach and run in background\n");
    fprintf(stderr, "  -v, --version             Print version information and exit\n");
    fprintf(stderr, "  -x, --debug               Enable extra debug output\n");
    fprintf(stderr, "  -c, --config    <config>  Specify config file\n");
    fprintf(stderr, "  -r, --noremote            Don't fetch remote schedules\n");
    fprintf(stderr, "  -I, --interface <iface>   Override source interface name\n");
    fprintf(stderr, "  -4, --ipv4      <address> Override source IPv4 address\n");
    fprintf(stderr, "  -6, --ipv6      <address> Override source IPv6 address\n");
}



static void print_version(char *prog) {
    /* TODO more information? list available tests? */
    printf("%s (%s)\n", prog, PACKAGE_STRING);
    printf("Report bugs to <%s>\n", PACKAGE_BUGREPORT);
    printf(" config dir: %s\n", AMP_CONFIG_DIR);
    printf(" client config dir: %s\n", AMP_CLIENT_CONFIG_DIR);
    printf(" schedule config dir: %s\n", SCHEDULE_DIR);
    printf(" nametable config dir: %s\n", NAMETABLE_DIR);
    printf(" default test dir: %s\n", AMP_TEST_DIRECTORY);
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
static void stop_running(__attribute__((unused))struct wand_signal_t *signal) {
    Log(LOG_INFO, "Received SIGINT, exiting event loop");
    ev_hdl->running = false;
}



/*
 * If measured gets sent a SIGHUP or SIGUSR1 then it should reload all the
 * available test modules and then re-read the schedule file taking into
 * account the new list of available tests.
 */
static void reload(__attribute__((unused))struct wand_signal_t *signal) {
    Log(LOG_INFO, "Received signal %d, reloading all configuration",
            signal->signum);

    /* cancel all scheduled tests (let running ones finish) */
    clear_test_schedule(signal->data);

    /* empty the nametable */
    clear_nametable();

    /* reload all test modules */
    unregister_tests();
    if ( register_tests(vars.testdir) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	exit(1);
    }

    /* re-read nametable files */
    read_nametable_dir(NAMETABLE_DIR);
    read_nametable_dir(vars.nametable_dir);

    /* re-read schedule files */
    read_schedule_dir(signal->data, SCHEDULE_DIR);
    read_schedule_dir(signal->data, vars.schedule_dir);
}



/*
 * Translate the configuration string for log level into a syslog level.
 */
static int callback_verify_loglevel(cfg_t *cfg, cfg_opt_t *opt,
        const char *value, void *result) {

    if ( strncasecmp(value, "debug", strlen("debug")) == 0 ) {
        *(int *)result = LOG_DEBUG;
    } else if ( strncasecmp(value, "info", strlen("info")) == 0 ) {
        *(int *)result = LOG_INFO;
    } else if ( strncasecmp(value, "notice", strlen("notice")) == 0 ) {
        *(int *)result = LOG_NOTICE;
    } else if ( strncasecmp(value, "warn", strlen("warn")) == 0 ) {
        *(int *)result = LOG_WARNING;
    } else if ( strncasecmp(value, "err", strlen("err")) == 0 ) {
        *(int *)result = LOG_ERR;
    } else if ( strncasecmp(value, "crit", strlen("crit")) == 0 ) {
        *(int *)result = LOG_CRIT;
    } else if ( strncasecmp(value, "alert", strlen("alert")) == 0 ) {
        *(int *)result = LOG_ALERT;
    } else if ( strncasecmp(value, "emerg", strlen("emerg")) == 0 ) {
        *(int *)result = LOG_EMERG;
    } else {
        cfg_error(cfg, "Invalid value for option %s: %s\n"
                "Possible values include: "
                "debug, info, notice, warn, err, crit, alert, emerg",
                opt->name, value);
        return -1;
    }
    return 0;
}



/*
 *
 */
static int parse_config(char *filename, struct amp_global_t *vars) {
    int ret;
    unsigned int i;
    cfg_t *cfg, *cfg_sub;

    cfg_opt_t opt_collector[] = {
        CFG_BOOL("vialocal", cfg_true, CFGF_NONE),
        CFG_STR("address", AMQP_SERVER, CFGF_NONE),
        CFG_INT("port", AMQP_PORT, CFGF_NONE),
        CFG_STR("vhost", AMQP_VHOST, CFGF_NONE),
        CFG_STR("exchange", "amp_exchange", CFGF_NONE),
        CFG_STR("routingkey", "test", CFGF_NONE),
        CFG_BOOL("ssl", cfg_false, CFGF_NONE),
        CFG_STR("cacert", AMQP_CACERT_FILE, CFGF_NONE),
        CFG_STR("key", AMQP_KEY_FILE, CFGF_NONE),
        CFG_STR("cert", AMQP_CERT_FILE, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opt_remotesched[] = {
        CFG_BOOL("fetch", cfg_false, CFGF_NONE),
        CFG_STR("url", NULL, CFGF_NONE),
        CFG_STR("cacert", NULL, CFGF_NONE),
        CFG_STR("key", NULL, CFGF_NONE),
        CFG_STR("cert", NULL, CFGF_NONE),
        CFG_INT("frequency", SCHEDULE_FETCH_FREQUENCY, CFGF_NONE),
        CFG_BOOL("identify", cfg_true, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opt_control[] = {
        CFG_BOOL("enabled", cfg_false, CFGF_NONE),
        CFG_STR("port", CONTROL_PORT, CFGF_NONE),
        CFG_STR("interface", NULL, CFGF_NONE),
        CFG_STR("ipv4", NULL, CFGF_NONE),
        CFG_STR("ipv6", NULL, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t measured_opts[] = {
	CFG_STR("ampname", NULL, CFGF_NONE),
	CFG_STR("testdir", AMP_TEST_DIRECTORY, CFGF_NONE),
	CFG_STR("interface", NULL, CFGF_NONE),
	CFG_STR("ipv4", NULL, CFGF_NONE),
	CFG_STR("ipv6", NULL, CFGF_NONE),
        CFG_INT_CB("loglevel", LOG_INFO, CFGF_NONE, &callback_verify_loglevel),
        CFG_STR_LIST("nameservers", NULL, CFGF_NONE),
	CFG_SEC("collector", opt_collector, CFGF_NONE),
        CFG_SEC("remotesched", opt_remotesched, CFGF_NONE),
        CFG_SEC("control", opt_control, CFGF_NONE),
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

    if ( cfg_getstr(cfg, "ampname") != NULL ) {
        /* ampname has been set by the user, use it as is */
        vars->ampname = strdup(cfg_getstr(cfg, "ampname"));
    } else {
        /* ampname has not been set by the user, use the hostname instead */
        char hostname[HOST_NAME_MAX + 1];
        memset(hostname, 0, HOST_NAME_MAX + 1);
        if ( gethostname(hostname, HOST_NAME_MAX) == 0 ) {
            vars->ampname = strdup(hostname);
        } else {
            Log(LOG_ALERT, "Failed to guess ampname from hostname, aborting.");
            return -1;
        }
    }
    vars->testdir = strdup(cfg_getstr(cfg, "testdir"));
    /* only use configured loglevel if it's not forced on the command line */
    if ( !log_level_override ) {
        log_level = cfg_getint(cfg, "loglevel");
    }

    /* should we be testing using a particular interface */
    if ( vars->interface == NULL && cfg_getstr(cfg, "interface") != NULL ) {
        vars->interface = strdup(cfg_getstr(cfg, "interface"));
    }

    /* should we be testing using a particular source ipv4 address */
    if ( vars->sourcev4 == NULL && cfg_getstr(cfg, "ipv4") != NULL ) {
        vars->sourcev4 = strdup(cfg_getstr(cfg, "ipv4"));
    }

    /* should we be testing using a particular source ipv6 address */
    if ( vars->sourcev6 == NULL && cfg_getstr(cfg, "ipv6") != NULL ) {
        vars->sourcev6 = strdup(cfg_getstr(cfg, "ipv6"));
    }

    /* should we override /etc/resolv.conf and use our own nameservers */
    /* XXX rework the logic of this portion to repeat less code */
    if ( cfg_size(cfg, "nameservers") > 0 ) {
        int nscount = cfg_size(cfg, "nameservers");
        char *nameservers[nscount];
        for ( i=0; i<nscount; i++ ) {
            nameservers[i] = cfg_getnstr(cfg, "nameservers", i);
        }
        vars->ctx = amp_resolver_context_init(nameservers, nscount,
                vars->sourcev4, vars->sourcev6);
    } else {
        vars->ctx = amp_resolver_context_init(NULL, 0, vars->sourcev4,
                vars->sourcev6);
    }

    if ( vars->ctx == NULL ) {
        Log(LOG_ALERT, "Failed to configure resolver, aborting.");
        return -1;
    }

    /* parse the config for the collector we should report data to */
    for ( i=0; i<cfg_size(cfg, "collector"); i++ ) {
        cfg_sub = cfg_getnsec(cfg, "collector", i);
        vars->vialocal = cfg_getbool(cfg_sub, "vialocal");
        vars->collector = strdup(cfg_getstr(cfg_sub, "address"));
        vars->port = cfg_getint(cfg_sub, "port");
        vars->vhost = strdup(cfg_getstr(cfg_sub, "vhost"));
        vars->exchange = strdup(cfg_getstr(cfg_sub, "exchange"));
        vars->routingkey = strdup(cfg_getstr(cfg_sub, "routingkey"));
        vars->ssl = cfg_getbool(cfg_sub, "ssl");
        vars->amqp_ssl.cacert = strdup(cfg_getstr(cfg_sub, "cacert"));
        vars->amqp_ssl.key = strdup(cfg_getstr(cfg_sub, "key"));
        vars->amqp_ssl.cert = strdup(cfg_getstr(cfg_sub, "cert"));
    }

    /* parse the config for remote fetching of schedule files */
    for ( i=0; i<cfg_size(cfg, "remotesched"); i++ ) {
        cfg_sub = cfg_getnsec(cfg, "remotesched", i);
        /* check that it is enabled */
        vars->fetch_remote = cfg_getbool(cfg_sub, "fetch");

        if ( cfg_getstr(cfg_sub, "url") != NULL ) {
            /* tack the ampname on the end if we need to identify ourselves */
            if ( cfg_getbool(cfg_sub, "identify") ) {
                if ( asprintf(&vars->schedule_url, "%s?ampname=%s",
                            cfg_getstr(cfg_sub, "url"), vars->ampname) < 0 ) {
                    Log(LOG_ALERT, "Failed to build schedule fetching url");
                    return -1;
                }
            } else {
                vars->schedule_url = strdup(cfg_getstr(cfg_sub, "url"));
            }

            vars->fetch_freq = cfg_getint(cfg_sub, "frequency");

            if ( cfg_getstr(cfg_sub, "cacert") ) {
                vars->fetch_ssl.cacert = strdup(cfg_getstr(cfg_sub, "cacert"));
            }

            if ( cfg_getstr(cfg_sub, "key") ) {
                vars->fetch_ssl.key = strdup(cfg_getstr(cfg_sub, "key"));
            }

            if ( cfg_getstr(cfg_sub, "cert") ) {
                vars->fetch_ssl.cert = strdup(cfg_getstr(cfg_sub, "cert"));
            }
        }
    }

    /*
     * Parse the config for the control socket. It will only start if enabled
     * and SSL gets set up properly. It uses the same SSL settings as for
     * reporting data, so they don't need to be configured here.
     */
    for ( i=0; i<cfg_size(cfg, "control"); i++ ) {
        cfg_sub = cfg_getnsec(cfg, "control", i);
        vars->control_enabled = cfg_getbool(cfg_sub, "enabled");
        vars->control_port = strdup(cfg_getstr(cfg_sub, "port"));

        /*
         * If the control interface is not set, then use the globally set
         * interface (if that is set). Otherwise don't set the interface.
         */
        if ( cfg_getstr(cfg_sub, "interface") != NULL ) {
            vars->control_interface = strdup(cfg_getstr(cfg_sub, "interface"));
        } else if ( vars->interface != NULL ) {
            vars->control_interface = vars->interface;
        }

        /*
         * If the IPv4 address for the control interface is not set, then use
         * the globally set IPv4 address (if that is set), otherwise listen on
         * all addresses.
         */
        if ( cfg_getstr(cfg_sub, "ipv4") != NULL ) {
            vars->control_ipv4 = strdup(cfg_getstr(cfg_sub, "ipv4"));
        } else {
            if ( vars->sourcev4 != NULL ) {
                vars->control_ipv4 = vars->sourcev4; //XXX no need to copy?
            } else {
                vars->control_ipv4 = strdup("0.0.0.0");
            }
        }
        /*
         * If the IPv6 address for the control interface is not set, then use
         * the globally set IPv6 address (if that is set), otherwise listen on
         * all addresses.
         */
        if ( cfg_getstr(cfg_sub, "ipv6") != NULL ) {
            vars->control_ipv6 = strdup(cfg_getstr(cfg_sub, "ipv6"));
        } else {
            if ( vars->sourcev6 != NULL ) {
                vars->control_ipv6 = vars->sourcev6; //XXX no need to copy?
            } else {
                vars->control_ipv6 = strdup("::");
            }
        }
    }

    cfg_free(cfg);
    return 0;
}



/*
 *
 */
int main(int argc, char *argv[]) {
    struct wand_signal_t sigint_ev;
    struct wand_signal_t sigchld_ev;
    struct wand_signal_t sighup_ev;
    struct wand_signal_t sigusr1_ev;
    struct wand_fdcb_t control_ipv4_ev;
    struct wand_fdcb_t control_ipv6_ev;
    struct wand_fdcb_t nssock_ev;
    struct wand_timer_t fetch_ev;
    char *config_file = NULL;
    char *pidfile = NULL;
    int fetch_remote = 1;
    int backgrounded = 0;
    int configure_rabbit = 0;

    while ( 1 ) {

	int opt_ind = 0;
	int c = getopt_long(argc, argv, "dfhp:vxc:rI:4:6:",
                long_options, &opt_ind);
	if ( c == -1 )
	    break;

	switch ( c ) {
	    case 'd':
		/* daemonise, detach, close stdin/out/err, etc */
		if ( daemon(0, 0) < 0 ) {
		    perror("daemon");
		    return -1;
		}
                backgrounded = 1;
		break;
            case 'f':
                /*
                 * Configure rabbit user, create shovel and exit (needs to
                 * happen after config parsing though, so we know what
                 * configuration to perform
                 */
                configure_rabbit = 1;
                break;
	    case 'v':
		/* print version and build info */
                print_version(argv[0]);
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
                vars.interface = optarg;
                break;
            case '4':
                /* override config settings and set the source IPv4 address */
                vars.sourcev4 = optarg;
                break;
            case '6':
                /* override config settings and set the source IPv6 address */
                vars.sourcev6 = optarg;
                break;
	    case 'h':
	    default:
		usage();
		exit(0);
	};
    }

#if LOG_TO_SYSLOG
    /*
     * We are going to mess with argv later, which can mess with process
     * identfication. Lets force it to always be named after the package.
     */
    openlog(PACKAGE, LOG_PID, LOG_USER);
#endif

    Log(LOG_INFO, "amplet2 starting");

    if ( !config_file ) {
	config_file = AMP_CLIENT_CONFIG_DIR "/default.conf";
    }

    if ( parse_config(config_file, &vars) < 0 ) {
	return -1;
    }

    /*
     * Try to configure the local rabbitmq broker and then exit. Ideally this
     * probably shouldn't be lumped in with the amplet client code, but it
     * needs to have all the configuration parsing performed so it knows what
     * to do.
     */
    if ( configure_rabbit ) {
        Log(LOG_INFO, "Configuring rabbitmq for amplet2 client %s",
                vars.ampname);

        if ( vars.vialocal ) {
            /*
             * If we are using a local broker to give more resiliency then
             * we should make our own user and vhost, give ourselves a private
             * space to operate within.
             */
            if ( setup_rabbitmq_user(vars.ampname) < 0 ) {
                Log(LOG_ALERT, "Failed to create user, aborting");
                return -1;
            }

            /*
             * The shovel is used to send data from our local queues to the
             * remote collector via an SSL secured connection.
             */
             //XXX add echange and routing key
            if ( setup_rabbitmq_shovel(vars.ampname, vars.collector,
                        vars.port, vars.amqp_ssl.cacert, vars.amqp_ssl.cert,
                        vars.amqp_ssl.key, vars.exchange, vars.routingkey)
                    < 0 ) {
                Log(LOG_ALERT, "Failed to create shovel, aborting");
                return -1;
            }
            Log(LOG_INFO, "Done configuring rabbitmq");
        } else {
            /*
             * If we aren't using a local broker then there is no configuration
             * to perform - we are reporting directly to a remote broker that
             * we can't really configure from here.
             */
            Log(LOG_WARNING, "vialocal = false, no local configuration");
        }

        exit(0);
    }

    /* save the pointer to argv so that we can overwrite the name later */
    vars.argc = argc;
    vars.argv = argv;

    /*
     * TODO do we always want to create the pidfile, or only when daemonised?
     * or only when explicitly set?
     */
    if ( pidfile && create_pidfile(pidfile) < 0 ) {
        Log(LOG_WARNING, "Failed to create pidfile %s, aborting", pidfile);
        return -1;
    }

    /* reset optind so the tests can call getopt normally on it's arguments */
    optind = 1;

    /* load all the test modules */
    if ( register_tests(vars.testdir) == -1) {
	Log(LOG_ALERT, "Failed to register tests, aborting.");
	return -1;
    }

    /*
     * Set up SSL certificates etc. This has to go before curl_global_init()
     * because if we fail then we clean up a whole lot of openssl stuff.
     * TODO determine which bits we can clean up and which bits we can't.
     */
    if ( (ssl_ctx = initialise_ssl()) == NULL ) {
        Log(LOG_WARNING, "Failed to initialise SSL, disabling control socket");
    }

    /* set up curl while we are still the only measured process running */
    curl_global_init(CURL_GLOBAL_ALL);

    /* set up event handlers */
    wand_event_init();
    ev_hdl = wand_create_event_handler();
    assert(ev_hdl);

    /* construct our custom, per-client directories for configs */
    if ( asprintf(&vars.schedule_dir, "%s/%s", SCHEDULE_DIR,
                vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build custom schedule directory path");
        return -1;
    }

    if ( asprintf(&vars.nametable_dir, "%s/%s", NAMETABLE_DIR,
                vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build custom nametable directory path");
        return -1;
    }

    /* construct our custom, per-client nameserver socket */
    if ( asprintf(&vars.nssock, "%s/%s.sock", AMP_RUN_DIR,
                vars.ampname) < 0 ) {
        Log(LOG_ALERT, "Failed to build local resolve socket path");
        return -1;
    }

    /* fetch remote schedule configuration if it is fresher than what we have */
    if ( fetch_remote && vars.fetch_remote ) {
        if ( vars.schedule_url == NULL ) {
            Log(LOG_WARNING,
                    "Remote schedule enabled but no url set, skipping");
        } else {
            schedule_item_t *item;
            fetch_schedule_item_t *fetch_item;

            /* do a fetch now, while blocking the main process */
            update_remote_schedule(vars.schedule_dir, vars.schedule_url,
                    vars.fetch_ssl.cacert, vars.fetch_ssl.cert,
                    vars.fetch_ssl.key);

            /* save the arguments so we can use them again later */
            fetch_item = (fetch_schedule_item_t *)
                malloc(sizeof(fetch_schedule_item_t));
            fetch_item->schedule_dir = vars.schedule_dir;
            fetch_item->schedule_url = vars.schedule_url;
            fetch_item->cacert = vars.fetch_ssl.cacert;
            fetch_item->cert = vars.fetch_ssl.cert;
            fetch_item->key = vars.fetch_ssl.key;

            item = (schedule_item_t *)malloc(sizeof(schedule_item_t));
            item->type = EVENT_FETCH_SCHEDULE;
            item->ev_hdl = ev_hdl;
            item->data.fetch = fetch_item;

            /* create the timer event for fetching schedules */
            fetch_ev.expire = wand_calc_expire(ev_hdl, vars.fetch_freq, 0);
            fetch_ev.callback = remote_schedule_callback;
            fetch_ev.data = item;
            fetch_ev.prev = NULL;
            fetch_ev.next = NULL;
            wand_add_timer(ev_hdl, &fetch_ev);
        }
    }

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

    /* create the resolver/cache unix socket and add event listener for it */
    if ( (nssock_ev.fd = initialise_resolver_socket(vars.nssock)) < 0 ) {
        Log(LOG_ALERT, "Failed to initialise local resolver, aborting");
        return -1;
    }
    nssock_ev.flags = EV_READ;
    nssock_ev.data = vars.ctx;
    nssock_ev.callback = resolver_socket_event_callback;
    wand_add_event(ev_hdl, &nssock_ev);


    /* create the control socket and add an event listener for it */
    if ( vars.control_enabled && ssl_ctx != NULL ) {
        struct socket_t sockets;
        if ( initialise_control_socket(&sockets, vars.control_interface,
                    vars.control_ipv4, vars.control_ipv6,
                    vars.control_port) < 0 ) {
            Log(LOG_WARNING, "Failed to start control server");
        } else {
            /* if we have an ipv4 socket then set up the event listener */
            if ( sockets.socket > 0 ) {
                control_ipv4_ev.fd = sockets.socket;
                control_ipv4_ev.flags = EV_READ;
                control_ipv4_ev.data = ev_hdl;
                control_ipv4_ev.callback = control_establish_callback;
                wand_add_event(ev_hdl, &control_ipv4_ev);
            }
            /* if we have an ipv6 socket then set up the event listener */
            if ( sockets.socket6 > 0 ) {
                control_ipv6_ev.fd = sockets.socket6;
                control_ipv6_ev.flags = EV_READ;
                control_ipv6_ev.data = ev_hdl;
                control_ipv6_ev.callback = control_establish_callback;
                wand_add_event(ev_hdl, &control_ipv6_ev);
            }
        }
    }

    /*
     * Set up handler to deal with SIGHUP to reload available tests if running
     * without a TTY. With a TTY we want SIGHUP to terminate measured.
     */
    if ( backgrounded ) {
        sighup_ev.signum = SIGHUP;
        sighup_ev.callback = reload;
        sighup_ev.data = ev_hdl;
        wand_add_signal(&sighup_ev);
    }

    /* SIGUSR1 should also reload tests/schedules, we use this internally */
    sigusr1_ev.signum = SIGUSR1;
    sigusr1_ev.callback = reload;
    sigusr1_ev.data = ev_hdl;
    wand_add_signal(&sigusr1_ev);

    /* read the nametable to get a list of all test targets */
    read_nametable_dir(NAMETABLE_DIR);
    read_nametable_dir(vars.nametable_dir);

    /* read the schedule file to create the initial test schedule */
    read_schedule_dir(ev_hdl, SCHEDULE_DIR);
    read_schedule_dir(ev_hdl, vars.schedule_dir);

    /* give up control to libwandevent */
    wand_event_run(ev_hdl);

    /* if we get control back then it's time to tidy up */
    /* TODO what to do about scheduled tasks such as watchdogs? */
    clear_test_schedule(ev_hdl);
    clear_nametable();
    wand_del_signal(&sigint_ev);
    wand_del_signal(&sigchld_ev);
    if ( backgrounded ) {
        wand_del_signal(&sighup_ev);
    }
    wand_destroy_event_handler(ev_hdl);

    if ( vars.fetch_remote && vars.schedule_url ) {
        free(vars.schedule_url);
    }
    free(vars.schedule_dir);
    free(vars.nametable_dir);
    free(vars.nssock);

    amp_resolver_context_delete(vars.ctx);

    ssl_cleanup();

    /* finish up with curl */
    /* TODO what if we are in the middle of updating remote schedule files? */
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

    Log(LOG_INFO, "Shutting down");

    return 0;
}
