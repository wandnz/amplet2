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

#include <confuse.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"
#include "debug.h"
#include "schedule.h"
#include "control.h"
#include "parseconfig.h"
#include "messaging.h"
#include "global.h"
#include "testlib.h"
#include "acl.h"
#include "dscp.h"
#include "rabbitcfg.h"



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
 * Callback to verify that the DSCP value given in the configuration is a
 * valid name of a differentiated services code point, or a numeric value
 * that contains a 6-bit value.
 */
static int callback_verify_dscp(cfg_t *cfg, cfg_opt_t *opt,
        const char *value, void *result) {

    if ( parse_dscp_value(value, (uint8_t *)result) < 0 ) {
        cfg_error(cfg, "Invalid value for option %s: %s\n"
                "Use 6 bit binary codepoint or shortname string",
                opt->name, value);
        return -1;
    }

    return 0;
}



/*
 * ampname has not been set by the user, so try to use the hostname instead
 */
static char* guess_ampname(void) {
    struct addrinfo hints, *addrinfo, *tmpaddr;
    char hostname[HOST_NAME_MAX + 1];
    char *ampname;

    /* hostname() will return just the hostname portion */
    memset(hostname, 0, HOST_NAME_MAX + 1);
    if ( gethostname(hostname, HOST_NAME_MAX) < 0 || strlen(hostname) == 0 ) {
        Log(LOG_ALERT, "Failed to get hostname: %s", strerror(errno));
        return NULL;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    /*
     * Try to find the FQDN based on the hostname - this should hit
     * /etc/hosts if the host is configured sensibly, but it could end up
     * asking a remote name server (and not one that AMP has configured).
     * Manually set an ampname if you don't like it.
     */
    if ( getaddrinfo(hostname, NULL, &hints, &addrinfo) < 0 ) {
        return strdup(hostname);
    }

    /*
     * Not sure if it is even possible for this to be NULL, but check
     * all the results until we find a non-null canonical name
     */
    for ( tmpaddr = addrinfo; tmpaddr != NULL; tmpaddr = tmpaddr->ai_next ) {
        if ( tmpaddr->ai_canonname != NULL &&
                strlen(tmpaddr->ai_canonname) > 0 ) {
            /* stop as soon as we find the first valid canonical name */
            break;
        }
    }

    if ( tmpaddr == NULL ) {
        /* no valid canonical name found, use the hostname we found earlier */
        ampname = strdup(hostname);
    } else {
        /* take the first non-null result, though there may be others */
        ampname = strdup(tmpaddr->ai_canonname);
    }

    freeaddrinfo(addrinfo);

    return ampname;
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

    cfg_sub = cfg_getsec(cfg, "ssl");

    if ( cfg_sub && (int)cfg_getbool(cfg_sub, "waitforcert") != -1 ) {
        return cfg_getbool(cfg_sub, "waitforcert");
    }

    /* try the deprecated settings in the collector section */
    cfg_sub = cfg_getsec(cfg, "collector");

    if ( cfg_sub && (int)cfg_getbool(cfg_sub, "waitforcert") != -1 ) {
        return cfg_getbool(cfg_sub, "waitforcert");
    }

    /* return the default value if neither option is set */
    return cfg_true;
}



/*
 * Get the SSL config from a section (either "ssl" or the deprecated
 * "collector") and return if anything was actually set.
 */
static int get_ssl_config(cfg_t *cfg_sub, amp_ssl_opt_t *amqp_ssl) {
    int set = 0;

    assert(cfg_sub);
    assert(amqp_ssl);

    /* if these aren't set, then they will be generated later if required */
    if ( cfg_getstr(cfg_sub, "cacert") ) {
        amqp_ssl->cacert = strdup(cfg_getstr(cfg_sub, "cacert"));
        set = 1;
    } else {
        amqp_ssl->cacert = NULL;
    }

    if ( cfg_getstr(cfg_sub, "key") ) {
        amqp_ssl->key = strdup(cfg_getstr(cfg_sub, "key"));
        set = 1;
    } else {
        amqp_ssl->key = NULL;
    }

    if ( cfg_getstr(cfg_sub, "cert") ) {
        amqp_ssl->cert = strdup(cfg_getstr(cfg_sub, "cert"));
        set = 1;
    } else {
        amqp_ssl->cert = NULL;
    }

    /*
     * if we set anything, then this is the true ssl config. If the waitforcert
     * option isn't set, set it ourselves now so that it doesn't get the chance
     * to fall through if the value is set later in a deprecated section.
     */
    if ( set && (int)cfg_getbool(cfg_sub, "waitforcert") == -1 ) {
        cfg_setbool(cfg_sub, "waitforcert", cfg_true);
    } else if ( !set && (int)cfg_getbool(cfg_sub, "waitforcert") != -1 ) {
        set = 1;
    }

    return set;
}



/*
 * Parse the config for the control socket. It will only start if enabled
 * and SSL gets set up properly. It uses the same SSL settings as for
 * reporting data, so they don't need to be configured here.
 */
amp_control_t* get_control_config(cfg_t *cfg, amp_test_meta_t *meta) {
    amp_control_t* control = NULL;
    cfg_t *cfg_sub, *cfg_acl;
    unsigned int i;

    assert(cfg);
    cfg_sub = cfg_getsec(cfg, "control");

    if ( cfg_sub ) {
        control = (amp_control_t *) malloc(sizeof(amp_control_t));

        control->acl = initialise_acl();
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

        /* build up the access control lists for the control socket */
        for ( i = 0; i < cfg_size(cfg_sub, "acl"); i++ ) {
            unsigned int j;
            uint8_t property;

            cfg_acl = cfg_getnsec(cfg_sub, "acl", i);

            if ( strcmp(cfg_title(cfg_acl), "server") == 0 ) {
                property = ACL_SERVER;
            } else if ( strcmp(cfg_title(cfg_acl), "test") == 0 ) {
                property = ACL_TEST;
            } else if ( strcmp(cfg_title(cfg_acl), "schedule") == 0 ) {
                property = ACL_SCHEDULE;
            } else {
                continue;
            }

            /*
             * Add all the allow rules first, so that if it is "all" it will
             * update the root node and be inherited properly.
             */
            for ( j = 0; j < cfg_size(cfg_acl, "allow"); j++ ) {
                add_acl(control->acl, cfg_getnstr(cfg_acl, "allow", j),
                        property, 1);
            }

            for ( j = 0; j < cfg_size(cfg_acl, "deny"); j++ ) {
                add_acl(control->acl, cfg_getnstr(cfg_acl, "deny", j),
                        property, 0);
            }
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

        fetch = (fetch_schedule_item_t *)
            calloc(1, sizeof(fetch_schedule_item_t));

        if ( cfg_getstr(cfg_sub, "url") != NULL ) {
            /* need to determine the specific client schedule_dir */
            if ( asprintf(&fetch->schedule_dir, "%s/%s", SCHEDULE_DIR,
                        vars.ampname) < 0 ) {
                Log(LOG_ALERT, "Failed to build schedule directory path");
                free(fetch);
                return NULL;
            }

            /* tack the ampname on the end if we need to identify ourselves */
            if ( cfg_getbool(cfg_sub, "identify") ) {
                if ( asprintf(&fetch->schedule_url, "%s%s",
                            cfg_getstr(cfg_sub, "url"), vars.ampname) < 0 ) {
                    Log(LOG_ALERT, "Failed to build schedule fetching url");
                    free(fetch->schedule_dir);
                    free(fetch);
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

    /* set the default differentiated services bits */
    if ( meta->dscp == DEFAULT_DSCP_VALUE ) {
        meta->dscp = cfg_getint(cfg, "dscp");
    }

    return meta;
}



/*
 * Parse the DNS nameserver configuration from the config file and return
 * a DNS context initialised using those servers.
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
    cfg_t *cfg, *cfg_sub;
    cfg_bool_t default_vialocal;
    int set_ssl;

    /* if rabbitmq exists on the system, then default to using it */
    if ( check_exists(RABBITMQCTL, 0) == 0 ) {
        default_vialocal = cfg_true;
    } else {
        default_vialocal = cfg_false;
    }

    cfg_opt_t opt_ssl[] = {
        CFG_STR("cacert", NULL, CFGF_NONE),
        CFG_STR("key", NULL, CFGF_NONE),
        CFG_STR("cert", NULL, CFGF_NONE),
        /*
         * XXX can't set a sensible default here while deprecated option
         * exists. Use -1 so we can tell when it get set later
         */
        CFG_BOOL("waitforcert", -1, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opt_collector[] = {
        CFG_BOOL("vialocal", default_vialocal, CFGF_NONE),
        CFG_STR("local", AMQP_SERVER, CFGF_NONE),
        CFG_BOOL("configrabbit", cfg_true, CFGF_NONE),
        CFG_STR("address", NULL, CFGF_NONE),
        CFG_INT("port", AMQP_PORT, CFGF_NONE),
        CFG_STR("vhost", AMQP_VHOST, CFGF_NONE),
        CFG_STR("exchange", "amp_exchange", CFGF_NONE),
        CFG_STR("routingkey", "test", CFGF_NONE),
        CFG_BOOL("ssl", cfg_false, CFGF_NONE),
        /* deprecated, will be ignored if global ssl options are set */
        CFG_STR("cacert", NULL, CFGF_NONE),
        CFG_STR("key", NULL, CFGF_NONE),
        CFG_STR("cert", NULL, CFGF_NONE),
        CFG_BOOL("waitforcert", -1, CFGF_NONE),
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

    cfg_opt_t opt_acl[] = {
        CFG_STR_LIST("allow", NULL, CFGF_NONE),
        CFG_STR_LIST("deny", NULL, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opt_control[] = {
        CFG_BOOL("enabled", cfg_false, CFGF_NONE),
        CFG_STR("port", DEFAULT_AMPLET_CONTROL_PORT, CFGF_NONE),
        CFG_STR("interface", NULL, CFGF_NONE),
        CFG_STR("ipv4", NULL, CFGF_NONE),
        CFG_STR("ipv6", NULL, CFGF_NONE),
        CFG_SEC("acl", opt_acl, CFGF_TITLE | CFGF_MULTI),
        CFG_END()
    };

    cfg_opt_t measured_opts[] = {
	CFG_STR("ampname", NULL, CFGF_NONE),
	CFG_STR("interface", NULL, CFGF_NONE),
	CFG_STR("ipv4", NULL, CFGF_NONE),
	CFG_STR("ipv6", NULL, CFGF_NONE),
        CFG_INT("packetdelay", MIN_INTER_PACKET_DELAY, CFGF_NONE),
        CFG_INT_CB("loglevel", LOG_INFO, CFGF_NONE, &callback_verify_loglevel),
        CFG_INT_CB("dscp", DEFAULT_DSCP_VALUE, CFGF_NONE,&callback_verify_dscp),
        CFG_STR_LIST("nameservers", NULL, CFGF_NONE),
	CFG_SEC("ssl", opt_ssl, CFGF_NONE),
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
	Log(LOG_ALERT, "Failed to parse config file '%s', aborting.", filename);
	return NULL;
    }

    if ( cfg_getstr(cfg, "ampname") != NULL ) {
        /* ampname has been set by the user, use it as is */
        vars->ampname = strdup(cfg_getstr(cfg, "ampname"));
    } else {
        if ( (vars->ampname = guess_ampname()) == NULL ) {
            cfg_free(cfg);
            return NULL;
        }
    }

    /* parse the config for the global SSL configuration */
    cfg_sub = cfg_getsec(cfg, "ssl");
    if ( cfg_sub ) {
        set_ssl = get_ssl_config(cfg_sub, &vars->amqp_ssl);
    } else {
        /* default values means this should never be reached */
        set_ssl = 0;
    }

    /* parse the config for the collector we should report data to */
    cfg_sub = cfg_getsec(cfg, "collector");
    if ( cfg_sub ) {
        if ( cfg_getstr(cfg_sub, "address") == NULL ) {
            cfg_free(cfg);
            Log(LOG_ALERT, "No collector address in config file '%s', aborting",
                    filename);
            return NULL;
        }

        vars->collector = strdup(cfg_getstr(cfg_sub, "address"));
        vars->vialocal = cfg_getbool(cfg_sub, "vialocal");
        vars->local = strdup(cfg_getstr(cfg_sub, "local"));
        vars->port = cfg_getint(cfg_sub, "port");
        vars->vhost = strdup(cfg_getstr(cfg_sub, "vhost"));
        vars->exchange = strdup(cfg_getstr(cfg_sub, "exchange"));
        vars->routingkey = strdup(cfg_getstr(cfg_sub, "routingkey"));
        vars->ssl = cfg_getbool(cfg_sub, "ssl");

        /* TODO remove deprecated options */
        if ( set_ssl && (cfg_getstr(cfg_sub, "cacert") != NULL ||
                cfg_getstr(cfg_sub, "cert") != NULL ||
                cfg_getstr(cfg_sub, "key") != NULL ||
                (int)cfg_getbool(cfg_sub, "waitforcert") != -1 ) ) {
            /* warn the user if they try to set both the old and new options */
            Log(LOG_WARNING,
                    "Ignoring deprecated ssl settings from collector section");
        } else if ( !set_ssl ) {
            /* if not set by ssl section, try to set in the collector section */
            if ( get_ssl_config(cfg_sub, &vars->amqp_ssl) ) {
                /* warn if the values changed - the collector section set it */
                Log(LOG_WARNING, "Missing ssl configuration, using deprecated "
                        "collector ssl settings. Update configuration file!");
            }
        }
    } else {
        cfg_free(cfg);
        Log(LOG_ALERT, "No collector section in config file '%s', aborting",
                filename);
        return NULL;
    }

    /* keep the config pointer around so we can query other parts of it */
    return cfg;
}
