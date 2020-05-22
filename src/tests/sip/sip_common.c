/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2019-2020 The University of Waikato, Hamilton, New Zealand.
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
#include <sys/socket.h>
#include <unistd.h>

#include <pjsua-lib/pjsua.h>
#include <pjsua-lib/pjsua_internal.h>

#include "config.h"
#include "tests.h"
#include "sip.h"
#include "debug.h"
#include "testlib.h"
#include "dscp.h"
#include "../../measured/control.h"


/*
 * Parse all the command line options and return an options structure.
 */
struct opt_t* parse_options(int argc, char *argv[]) {
    extern struct option long_options[];
    struct opt_t *options;
    int opt;

    options = calloc(1, sizeof(struct opt_t));
    options->user_agent = pj_str("AMP SIP test agent " PACKAGE_VERSION);
    options->filename = pj_str(SIP_WAV_FILE);
    options->max_duration = 30;
    options->repeat = 1;
    options->control_port = atoi(DEFAULT_AMPLET_CONTROL_PORT);
    /* port to bind to locally, use the URI to set remote port */
    options->sip_port = SIP_SERVER_LISTEN_PORT;
    options->dscp = DEFAULT_DSCP_VALUE;
    options->family = AF_UNSPEC;

    /* TODO transport TLS configuration, publicAddress? */
    /* TODO add STUN option? */
    /* TODO do non-sip, e.g. tel: ? */
    /* TODO device - can we use transport_config.sockopt_params? */
    while ( (opt = getopt_long(argc, argv,
                    "n:w:e:i:a:f:P:p:rst:u:y:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4': options->forcev4 = 1;
                      options->sourcev4 = parse_optional_argument(argv);
                      break;
            case '6': options->forcev6 = 1;
                      options->sourcev6 = parse_optional_argument(argv);
                      break;
            case 'Q': if ( parse_dscp_value(optarg, &options->dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'I': options->device = optarg; break;
            case 'n': options->username = pj_str(optarg); break;
            case 'w': options->password = pj_str(optarg); break;
            case 'e': if ( pjsua_verify_sip_url(optarg) != PJ_SUCCESS ) {
                          Log(LOG_WARNING, "Bad registrar URI: '%s'", optarg);
                          exit(EXIT_FAILURE);
                      }
                      options->registrar = pj_str(optarg);
                      break;
            case 'i': if ( pjsua_verify_sip_url(optarg) != PJ_SUCCESS ) {
                          Log(LOG_WARNING, "Bad id URI: '%s'", optarg);
                          exit(EXIT_FAILURE);
                      }
                      options->id = pj_str(optarg);
                      break;
            case 'a': options->user_agent = pj_str(optarg); break;
            case 'f': options->filename = pj_str(optarg); break;
            case 'P': options->sip_port = atoi(optarg); break;
            case 'p': options->control_port = atoi(optarg); break;
            case 'y': if ( pjsua_verify_sip_url(optarg) != PJ_SUCCESS ) {
                          fprintf(stderr, "Bad proxy: '%s'\n", optarg);
                          exit(EXIT_FAILURE);
                      }
                      options->outbound_proxy[options->outbound_proxy_cnt++] = pj_str(optarg);
                      break;
            case 'r': options->repeat = 0; break;
            case 't': options->max_duration = atoi(optarg); break;
            case 'u': if ( pjsua_verify_sip_url(optarg) != PJ_SUCCESS ) {
                          fprintf(stderr, "Bad URI: '%s'\n", optarg);
                          exit(EXIT_FAILURE);
                      }
                      options->uri = pj_str(optarg);
                      break;
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    return options;
}



/*
 * Convert a pj_str_t into a null terminated char pointer.
 */
char* copy_and_null_terminate(pj_str_t *src) {
    char *dst;

    if ( src->slen == 0 ) {
        return NULL;
    }

    dst = calloc(1, src->slen + 1);
    memcpy(dst, src->ptr, src->slen);

    return dst;
}



/*
 * Set some options to make SIP messages much smaller so hopefully they will
 * fit inside a single datagram.
 */
void set_use_minimal_messages(void) {
    /* enable compact form */
    extern pj_bool_t pjsip_use_compact_form;
    pjsip_use_compact_form = PJ_TRUE;

    /* do not transmit Allow header */
    extern pj_bool_t pjsip_include_allow_hdr_in_dlg;
    pjsip_include_allow_hdr_in_dlg = PJ_FALSE;

    /* keep this true for now to explicitly list all codecs */
    extern pj_bool_t pjmedia_add_rtpmap_for_static_pt;
    pjmedia_add_rtpmap_for_static_pt = PJ_TRUE;
}



/*
 * Hang up once the call has reached the maximum duration.
 */
static void on_timeout_callback(pj_timer_heap_t *timer_heap,
        struct pj_timer_entry *entry) {
    PJ_UNUSED_ARG(timer_heap);
    PJ_UNUSED_ARG(entry);

    Log(LOG_DEBUG, "Timer callback, hanging up");

    pjsua_call_hangup_all();
    free(entry);
}



/*
 * Hang up once the wav file has completed playback.
 */
static pj_status_t on_playfile_done(pjmedia_port *port, void *data) {
    PJ_UNUSED_ARG(port);
    PJ_UNUSED_ARG(data);

    Log(LOG_DEBUG, "Audio file playback complete");

    /*
     * XXX it appears that trying to hang up here causes a deadlock in pjsip,
     * so start a zero duration timer and hangup in the timer callback instead.
     */
    //pjsua_call_hangup_all();
    start_duration_timer(0);

    return PJ_SUCCESS;
}



/*
 * Load and start playing the wav file onto the call conference port.
 */
static pj_status_t start_playfile(pjsua_call_id call_id) {
    pj_status_t status;
    pjsua_player_id player_id;
    pjmedia_port *port;
    pjsua_conf_port_id wav_port;
    struct opt_t *options;

    /* the wav file to play is attached to the account data */
    options = (struct opt_t*)pjsua_acc_get_user_data(pjsua_acc_get_default());

    Log(LOG_DEBUG, "Creating wav player for %*s\n",
            (int)options->filename.slen, options->filename.ptr);

    status = pjsua_player_create(&options->filename,
            options->repeat ? 0 : PJMEDIA_FILE_NO_LOOP, &player_id);
    if ( status != PJ_SUCCESS ) {
        return status;
    }

    /* set callback to hang up call when the file is finished playing */
    if ( !options->repeat ) {
        pjsua_player_get_port(player_id, &port);
        status = pjmedia_wav_player_set_eof_cb(port, NULL, &on_playfile_done);
        if ( status != PJ_SUCCESS ) {
            return status;
        }
    }

    /* connect the output of the wav file to the input of the call */
    Log(LOG_DEBUG, "Connecting audio ports");
    wav_port = pjsua_player_get_conf_port(player_id);
    status = pjsua_conf_connect(wav_port, pjsua_call_get_conf_port(call_id));

    return status;
}



/*
 * Start the timer to limit call duration.
 */
void start_duration_timer(int duration) {
    pj_timer_entry *timer;
    pj_time_val delay;
    pjsip_endpoint *endpoint;

    timer = (pj_timer_entry*)malloc(sizeof(pj_timer_entry));
    pj_timer_entry_init(timer, 0, NULL, &on_timeout_callback);

    endpoint = pjsua_get_pjsip_endpt();
    delay.sec = duration;
    delay.msec = 0;
    pjsip_endpt_schedule_timer(endpoint, timer, &delay);
}



/*
 * Callback for when media state changes. Will start playback of the wav file
 * once the media connection becomes active.
 */
void on_call_media_state(pjsua_call_id call_id) {
    pjsua_call_info call_info;

    pjsua_call_get_info(call_id, &call_info);

    if ( call_info.media_status == PJSUA_CALL_MEDIA_ACTIVE ) {
        pj_status_t status;

        Log(LOG_DEBUG, "Call %d media is active", call_id);

        /* TODO should this happen here, or in the CONFIRMED call state? */
        status = start_playfile(call_id);

        if ( status != PJ_SUCCESS ) {
            char errmsg[PJ_ERR_MSG_SIZE];
            pj_strerror(status, errmsg, sizeof(errmsg));
            Log(LOG_WARNING, "Failed to start playing file: %s\n", errmsg);
            pjsua_call_hangup_all();
            exit(EXIT_FAILURE);
        }
    }
}



/*
 * Extract and return the host portion from a URI.
 */
char* get_host_from_uri(pj_pool_t *pool, pj_str_t uri_str) {
    pjsip_uri *uri;
    pjsip_sip_uri *sip_uri;
    char *buf;
    char *host;

    /* convert uri back into a null terminated string for pjsip_parse_uri */
    buf = copy_and_null_terminate(&uri_str);

    /* convert the uri string into a broken down structure */
    uri = pjsip_parse_uri(pool, buf, uri_str.slen, 0);
    sip_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(uri);

    /* sip_uri contains pointers into buf, so extract the host before freeing */
    host = copy_and_null_terminate(&sip_uri->host);
    free(buf);

    return host;
}



/*
 * Given a URI, return the address family that should be used to call it.
 * The URI should have been validated before this function is called.
 */
static uint8_t get_family_from_uri(pj_pool_t *pool, pj_str_t uri_str) {
    pj_sockaddr addr;
    pj_status_t status;
    pj_str_t host;

    host = pj_str(get_host_from_uri(pool, uri_str));

    /* try to determine if we are going to use ipv4 or ipv6 to reach the host */
    status = pj_getipinterface(AF_INET6, &host, &addr, PJ_TRUE, NULL);

    free(host.ptr);

    if ( status == PJ_SUCCESS ) {
        return AF_INET6;
    }

    /* just assume it's ipv4 at this point */
    return AF_INET;
}



/*
 * Register the specified transport.
 */
static pj_status_t register_transport(pj_pool_t *pool,
        pjsip_transport_type_e transport, pjsua_transport_config *cfg) {
    pjsua_transport_id trans_id;
    pjsua_acc_id account_id;
    pjsua_acc_config account_cfg;
    pj_status_t status;

    if ( (transport & ~PJSIP_TRANSPORT_IPV6) == PJSIP_TRANSPORT_UDP ) {
        Log(LOG_DEBUG, "Registering transport udp/%s",
                (transport & PJSIP_TRANSPORT_IPV6) ? "ipv6" : "ipv4");
    } else if ( (transport & ~PJSIP_TRANSPORT_IPV6) == PJSIP_TRANSPORT_TCP ) {
        Log(LOG_DEBUG, "Registering transport tcp/%s",
                (transport & PJSIP_TRANSPORT_IPV6) ? "ipv6" : "ipv4");
    } else {
        Log(LOG_DEBUG, "Registering transport unknown/%s",
                (transport & PJSIP_TRANSPORT_IPV6) ? "ipv6" : "ipv4");
    }

    status = pjsua_transport_create(transport, cfg, &trans_id);
    if ( status != PJ_SUCCESS ) {
        return status;
    }

    /* add a local account using this transport */
    pjsua_acc_add_local(trans_id, PJ_FALSE, &account_id);

#if PJ_VERSION_NUM >= 0x02020000
    pjsua_acc_get_config(account_id, pool, &account_cfg);
#else
    pjsua_acc_get_config(account_id, &account_cfg);
#endif

    /* set DSCP bits */
    account_cfg.rtp_cfg.qos_params = cfg->qos_params;

    /* if using IPv6, need to tell the media to use it as well */
    if ( transport & PJSIP_TRANSPORT_IPV6 ) {
        account_cfg.ipv6_media_use = PJSUA_IPV6_ENABLED;
    }

    pjsua_acc_modify(account_id, &account_cfg);

    return PJ_SUCCESS;
}



/*
 * Register all the required transports for one address family.
 */
static int register_family_transports(pj_pool_t *pool, int family,
        pjsua_transport_config *cfg) {
    unsigned i;
    int status;
    pjsip_transport_type_e transports[] = {
        PJSIP_TRANSPORT_UDP,
        PJSIP_TRANSPORT_TCP,
        /* TODO TLS */
        //PJSIP_TRANSPORT_TLS
    };

    for ( i = 0; i < sizeof(transports)/sizeof(pjsip_transport_type_e); i++ ) {
        pjsip_transport_type_e transport = transports[i];

        if ( family == AF_INET6 ) {
            transport += PJSIP_TRANSPORT_IPV6;
        }

        status = register_transport(pool, transport, cfg);
        if ( status != PJ_SUCCESS ) {
            return status;
        }
    }

    return PJ_SUCCESS;
}



/*
 * Register all the required transports for this test run.
 */
int register_transports(struct opt_t *options, int is_server) {
    int status;
    pj_pool_t *pool;
    pjsua_transport_config transport_config;

    Log(LOG_DEBUG, "Registering transports");

    pool = pjsua_pool_create("tmp-register-transports", 1000, 1000);

    /* determine which address families should register transports */
    if ( options->forcev4 && !options->forcev6 ) {
        options->family = AF_INET;
    } else if ( options->forcev6 && !options->forcev4 ) {
        options->family = AF_INET6;
    } else {
        if ( is_server ) {
            /* this is a server, use both address families */
            options->family = AF_UNSPEC;
        } else {
            /* try to guess one family based on the URI */
            options->family = get_family_from_uri(pool, options->uri);
        }
    }

    /* set common transport options */
    pjsua_transport_config_default(&transport_config);
    transport_config.port = options->sip_port;
    transport_config.qos_params.flags = PJ_QOS_PARAM_HAS_DSCP;
    transport_config.qos_params.dscp_val = options->dscp;

    /*
     * TODO transports need to be registered for the address family used to
     * reach the registrar as well, even if they aren't used for INVITE/media
     */

    /* register ipv4 transports */
    if ( options->family == AF_INET || options->family == AF_UNSPEC ) {
        struct pjsua_transport_config ipv4_config;
        pjsua_transport_config_dup(pool, &ipv4_config, &transport_config);

        if ( options->sourcev4 ) {
            ipv4_config.bound_addr = pj_str(options->sourcev4);
        }

        status = register_family_transports(pool, AF_INET, &ipv4_config);
        if ( status != PJ_SUCCESS ) {
            pj_pool_release(pool);
            return status;
        }
    }

    /* register ipv6 transports */
    if ( options->family == AF_INET6 || options->family == AF_UNSPEC ) {
        struct pjsua_transport_config ipv6_config;
        pjsua_transport_config_dup(pool, &ipv6_config, &transport_config);

        if ( options->sourcev6 ) {
            ipv6_config.bound_addr = pj_str(options->sourcev6);
        }

        status = register_family_transports(pool, AF_INET6, &ipv6_config);
        if ( status != PJ_SUCCESS ) {
            pj_pool_release(pool);
            return status;
        }
    }

    pj_pool_release(pool);

    return PJ_SUCCESS;
}



/*
 *
 */
pj_status_t register_account(struct opt_t *options) {
    pjsua_acc_config acc_cfg;
    pjsua_acc_info acc_info;
    int retry = 0;
    int status;

    /* only register with a server if authentication details are provided */
    if ( options->username.slen == 0 || options->registrar.slen == 0 ) {
        return PJ_SUCCESS;
    }

    /* need to configure another account, separate to local transports */
    pjsua_acc_config_default(&acc_cfg);

    acc_cfg.allow_sdp_nat_rewrite = PJ_TRUE;

    acc_cfg.reg_uri = options->registrar;
    acc_cfg.id = options->id;

    /*
     * XXX should be able to get all these by parsing a single URI,
     * but the pjsip library function to do so is broken and can't
     * deal with passwords properly
     */
    acc_cfg.cred_count = 1;
    acc_cfg.cred_info[0].realm = pj_str("*");
    acc_cfg.cred_info[0].username = options->username;
    acc_cfg.cred_info[0].scheme = pj_str("digest");

    if ( options->password.slen > 0 ) {
        acc_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
        acc_cfg.cred_info[0].data = options->password;
    }

    /* TODO set registration time down to slightly longer than test duration? */
    acc_cfg.reg_timeout = 60;

    /* XXX IPV6 DSCP needs version >= 2.6 of pjproject otherwise ignored */
    pjsua_transport_config rtp_cfg;
    pjsua_transport_config_default(&rtp_cfg);
    rtp_cfg.qos_params.flags = PJ_QOS_PARAM_HAS_DSCP;
    rtp_cfg.qos_params.dscp_val = options->dscp;
    acc_cfg.rtp_cfg = rtp_cfg;

    /*
     * I think this only matters for outgoing connections, so probably only
     * needs to be set if we know we are doing IPv6. It can only be
     * AF_UNSPEC if this is a server not knowing which family to listen on.
     */
    if ( /*options->family == AF_UNSPEC ||*/ options->family == AF_INET6 ) {
        acc_cfg.ipv6_media_use = PJSUA_IPV6_ENABLED;
    }

    if ( (status = pjsua_acc_add(&acc_cfg, PJ_TRUE, NULL)) != PJ_SUCCESS ) {
        return status;
    }

    /* wait for registration to complete */
    do {
        pjsua_acc_get_info(pjsua_acc_get_default(), &acc_info);
        Log(LOG_DEBUG, "Account status: %d", acc_info.status);
        sleep(1);
    } while ( acc_info.status == PJSIP_SC_TRYING && retry++ < 10 );

    if ( acc_info.status != PJSIP_SC_OK ) {
        const pj_str_t *text = pjsip_get_status_text(status);
        Log(LOG_WARNING, "Failed to register: %*s", text->slen, text->ptr);
        return PJ_EUNKNOWN;
    }

    return PJ_SUCCESS;
}



/*
 *
 */
pj_status_t register_codecs(void) {
    pj_str_t id;
    pj_status_t status;
    char **codec;
    char *enable[] = { "PCMA/8000", NULL };
    char *disable[] = {
        "PCMU/8000",
        "GSM/8000",
        "AMR/8000",
        "AMR-WB/16000",
        "opus/48000/2",
        "speex/32000",
        NULL
    };

    /* TODO allow changing priority of codecs? */
    for ( codec = enable; *codec != NULL; codec++ ) {
        status = pjsua_codec_set_priority(pj_cstr(&id, *codec),
                PJMEDIA_CODEC_PRIO_HIGHEST);
        if ( status != PJ_SUCCESS ) {
            return status;
        }
    }

    for ( codec = disable; *codec != NULL; codec++ ) {
        status = pjsua_codec_set_priority(pj_cstr(&id, *codec),
                PJMEDIA_CODEC_PRIO_DISABLED);
        if ( status != PJ_SUCCESS ) {
            return status;
        }
    }

    return PJ_SUCCESS;
}
