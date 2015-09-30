#include <config.h>
#include <confuse.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>

#include "debug.h"
#include "schedule.h"
#include "control.h"
#include "parseconfig.h"
#include "messaging.h"
#include "global.h"


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
 * Ensure that any value given for the minimum inter-packet delay is a
 * vaguely sensible value.
 */
static int callback_verify_packet_delay(cfg_t *cfg, cfg_opt_t *opt) {
    int value = cfg_opt_getnint(opt, cfg_opt_size(opt) - 1);

    /* force the inter packet delay to be between 0 and 1 second */
    if ( value < 0 || value > 1000000 ) {
        cfg_error(cfg, "Invalid value for option %s: %d\n"
                "Delay must be between 0 and 1000000 microseconds\n",
                opt->name, value);
        return -1;
    }
    return 0;
}



/*
 * Get the configured log level.
 */
int get_loglevel_config(cfg_t *cfg) {
    assert(cfg);
    return cfg_getint(cfg, "loglevel");
}



/*
 * Should rabbitmq be configured on start up?
 */
int should_config_rabbit(cfg_t *cfg) {
    cfg_t *cfg_sub;

    assert(cfg);
    cfg_sub = cfg_getsec(cfg, "collector");

    if ( cfg_sub ) {
        /* configuration needs to be enabled, and a local broker in use */
        return cfg_getbool(cfg_sub, "vialocal") &&
            cfg_getbool(cfg_sub, "configrabbit");
    }

    return 0;
}



/*
 * Should the client wait to receive an SSL certificate, or terminate if it
 * is missing?
 */
int should_wait_for_cert(cfg_t *cfg) {
    cfg_t *cfg_sub;

    assert(cfg);
    cfg_sub = cfg_getsec(cfg, "collector");

    if ( cfg_sub ) {
        return cfg_getint(cfg_sub, "waitforcert");
    }

    return 0;
}



/*
 * Parse the config for the control socket. It will only start if enabled
 * and SSL gets set up properly. It uses the same SSL settings as for
 * reporting data, so they don't need to be configured here.
 */
amp_control_t* get_control_config(cfg_t *cfg, amp_test_meta_t *meta) {
    amp_control_t* control = NULL;
    cfg_t *cfg_sub;

    assert(cfg);
    cfg_sub = cfg_getsec(cfg, "control");

    if ( cfg_sub ) {
        control = (amp_control_t *) malloc(sizeof(amp_control_t));

        control->enabled = cfg_getbool(cfg_sub, "enabled");
        control->port = strdup(cfg_getstr(cfg_sub, "port"));

        /*
         * If the control interface is not set, then use the globally set
         * interface (if that is set). Otherwise don't set the interface.
         */
        if ( cfg_getstr(cfg_sub, "interface") != NULL ) {
            control->interface = strdup(cfg_getstr(cfg_sub, "interface"));
        } else if ( meta->interface != NULL ) {
            control->interface = strdup(meta->interface);
        } else {
            control->interface = NULL;
        }

        /*
         * If the IPv4 address for the control interface is not set, then use
         * the globally set IPv4 address (if that is set), otherwise listen on
         * all addresses.
         */
        if ( cfg_getstr(cfg_sub, "ipv4") != NULL ) {
            control->ipv4 = strdup(cfg_getstr(cfg_sub, "ipv4"));
        } else if ( meta->sourcev4 ) {
            control->ipv4 = strdup(meta->sourcev4);
        } else {
            control->ipv4 = strdup("0.0.0.0");
        }

        /*
         * If the IPv6 address for the control interface is not set, then use
         * the globally set IPv6 address (if that is set), otherwise listen on
         * all addresses.
         */
        if ( cfg_getstr(cfg_sub, "ipv6") != NULL ) {
            control->ipv6 = strdup(cfg_getstr(cfg_sub, "ipv6"));
        } else if ( meta->sourcev6 ) {
            control->ipv6 = strdup(meta->sourcev6);
        } else {
            control->ipv6 = strdup("::");
        }
    }

    return control;
}



/*
 * Get the configuration structure that describes how remote schedule
 * fetching should be performed.
 */
fetch_schedule_item_t* get_remote_schedule_config(cfg_t *cfg) {
    fetch_schedule_item_t *fetch = NULL;
    cfg_t *cfg_sub;

    assert(cfg);

    /* parse the config for remote fetching of schedule files */
    cfg_sub = cfg_getsec(cfg, "remotesched");

    if ( cfg_sub ) {
        /* check that it is enabled otherwise we can ignore the section */
        if ( !cfg_getbool(cfg_sub, "fetch") ) {
            return NULL;
        }

        fetch = (fetch_schedule_item_t *) malloc(sizeof(fetch_schedule_item_t));

        if ( cfg_getstr(cfg_sub, "url") != NULL ) {
            /* tack the ampname on the end if we need to identify ourselves */
            if ( cfg_getbool(cfg_sub, "identify") ) {
                if ( asprintf(&fetch->schedule_url, "%s%s",
                            cfg_getstr(cfg_sub, "url"), vars.ampname) < 0 ) {
                    Log(LOG_ALERT, "Failed to build schedule fetching url");
                    return NULL;
                }
            } else {
                fetch->schedule_url = strdup(cfg_getstr(cfg_sub, "url"));
            }

            fetch->frequency = cfg_getint(cfg_sub, "frequency");

            if ( cfg_getstr(cfg_sub, "cacert") ) {
                fetch->cacert = strdup(cfg_getstr(cfg_sub,"cacert"));
            }

            if ( cfg_getstr(cfg_sub, "key") ) {
                fetch->key = strdup(cfg_getstr(cfg_sub, "key"));
            }

            if ( cfg_getstr(cfg_sub, "cert") ) {
                fetch->cert = strdup(cfg_getstr(cfg_sub, "cert"));
            }
        }
    }

    return fetch;
}



/*
 * Parse the config for test interface configuration. Most of this can be
 * set via the command line, so expect a structure that may or may not already
 * have values - anything that is already set takes precedence.
 */
amp_test_meta_t* get_interface_config(cfg_t *cfg, amp_test_meta_t *meta) {

    assert(cfg);
    assert(meta);

    /* should we be testing using a particular interface */
    if ( meta->interface == NULL && cfg_getstr(cfg, "interface") != NULL ) {
        meta->interface = strdup(cfg_getstr(cfg, "interface"));
    }

    /* should we be testing using a particular source ipv4 address */
    if ( meta->sourcev4 == NULL && cfg_getstr(cfg, "ipv4") != NULL ) {
        meta->sourcev4 = strdup(cfg_getstr(cfg, "ipv4"));
    }

    /* should we be testing using a particular source ipv6 address */
    if ( meta->sourcev6 == NULL && cfg_getstr(cfg, "ipv6") != NULL ) {
        meta->sourcev6 = strdup(cfg_getstr(cfg, "ipv6"));
    }

    /* set the minimum microsecond gap between sending test probes */
    if ( meta->inter_packet_delay == MIN_INTER_PACKET_DELAY ) {
        meta->inter_packet_delay = cfg_getint(cfg, "packetdelay");
    }

    return meta;
}



/*
 *
 */
struct ub_ctx* get_dns_context_config(cfg_t *cfg, amp_test_meta_t *meta) {
    /* should we override /etc/resolv.conf and use our own nameservers */
    if ( cfg_size(cfg, "nameservers") > 0 ) {
        unsigned int nscount = cfg_size(cfg, "nameservers");
        char *nameservers[nscount];
        unsigned int i;

        for ( i=0; i<nscount; i++ ) {
            nameservers[i] = cfg_getnstr(cfg, "nameservers", i);
        }

        /* use specified nameservers */
        return amp_resolver_context_init(nameservers, nscount,
                meta->sourcev4, meta->sourcev6);
    }

    /* use default nameservers */
    return amp_resolver_context_init(NULL, 0, meta->sourcev4, meta->sourcev6);
}



/*
 * Parse the config and set the generic options that we know are always
 * required. These options to into the global vars structure, which is slowly
 * being phased out as I figure out how to place the variables in the
 * appropriate locations.
 */
cfg_t* parse_config(char *filename, struct amp_global_t *vars) {

    int ret;
    unsigned int i;
    cfg_t *cfg, *cfg_sub;

    cfg_opt_t opt_collector[] = {
        CFG_BOOL("vialocal", cfg_true, CFGF_NONE),
        CFG_STR("local", AMQP_SERVER, CFGF_NONE),
        CFG_BOOL("configrabbit", cfg_true, CFGF_NONE),
        CFG_STR("address", AMQP_SERVER, CFGF_NONE),
        CFG_INT("port", AMQP_PORT, CFGF_NONE),
        CFG_STR("vhost", AMQP_VHOST, CFGF_NONE),
        CFG_STR("exchange", "amp_exchange", CFGF_NONE),
        CFG_STR("routingkey", "test", CFGF_NONE),
        CFG_BOOL("ssl", cfg_false, CFGF_NONE),
        CFG_STR("cacert", NULL, CFGF_NONE),
        CFG_STR("key", NULL, CFGF_NONE),
        CFG_STR("cert", NULL, CFGF_NONE),
        CFG_INT("waitforcert", -1, CFGF_NONE),
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
	CFG_STR("interface", NULL, CFGF_NONE),
	CFG_STR("ipv4", NULL, CFGF_NONE),
	CFG_STR("ipv6", NULL, CFGF_NONE),
        CFG_INT("packetdelay", MIN_INTER_PACKET_DELAY, CFGF_NONE),
        CFG_INT_CB("loglevel", LOG_INFO, CFGF_NONE, &callback_verify_loglevel),
        CFG_STR_LIST("nameservers", NULL, CFGF_NONE),
	CFG_SEC("collector", opt_collector, CFGF_NONE),
        CFG_SEC("remotesched", opt_remotesched, CFGF_NONE),
        CFG_SEC("control", opt_control, CFGF_NONE),
	CFG_END()
    };

    Log(LOG_INFO, "Parsing configuration file %s\n", filename);

    cfg = cfg_init(measured_opts, CFGF_NONE);
    cfg_set_validate_func(cfg, "packetdelay", callback_verify_packet_delay);

    ret = cfg_parse(cfg, filename);

    if ( ret == CFG_FILE_ERROR ) {
	cfg_free(cfg);
	Log(LOG_ALERT, "No such config file '%s', aborting.", filename);
	return NULL;
    }

    if ( ret == CFG_PARSE_ERROR ) {
	cfg_free(cfg);
	Log(LOG_ALERT, "Failed to parse config file '%s', aborting.",
		filename);
	return NULL;
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
            cfg_free(cfg);
            return NULL;
        }
    }

    /* parse the config for the collector we should report data to */
    for ( i=0; i<cfg_size(cfg, "collector"); i++ ) {
        cfg_sub = cfg_getnsec(cfg, "collector", i);
        vars->vialocal = cfg_getbool(cfg_sub, "vialocal");
        vars->local = strdup(cfg_getstr(cfg_sub, "local"));
        vars->collector = strdup(cfg_getstr(cfg_sub, "address"));
        vars->port = cfg_getint(cfg_sub, "port");
        vars->vhost = strdup(cfg_getstr(cfg_sub, "vhost"));
        vars->exchange = strdup(cfg_getstr(cfg_sub, "exchange"));
        vars->routingkey = strdup(cfg_getstr(cfg_sub, "routingkey"));
        vars->ssl = cfg_getbool(cfg_sub, "ssl");

        /* if these aren't set, then they will be generated later if required */
        if ( cfg_getstr(cfg_sub, "cacert") ) {
            vars->amqp_ssl.cacert = strdup(cfg_getstr(cfg_sub, "cacert"));
        } else {
            vars->amqp_ssl.cacert = NULL;
        }

        if ( cfg_getstr(cfg_sub, "key") ) {
            vars->amqp_ssl.key = strdup(cfg_getstr(cfg_sub, "key"));
        } else {
            vars->amqp_ssl.key = NULL;
        }

        if ( cfg_getstr(cfg_sub, "cert") ) {
            vars->amqp_ssl.cert = strdup(cfg_getstr(cfg_sub, "cert"));
        } else {
            vars->amqp_ssl.cert = NULL;
        }
    }

    /* keep the config pointer around so we can query other parts of it */
    return cfg;
}