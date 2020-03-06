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
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <pjsua-lib/pjsua.h>
#include <pjsua-lib/pjsua_internal.h>

#include "ssl.h"
#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "serverlib.h"
#include "sip.h"
#include "sip.pb-c.h"
#include "mos.h"
#include "debug.h"
#include "dscp.h"
#include "usage.h"
#include "../../measured/control.h"



/*
 * Print information about R factor and MOS.
 */
static void print_mos(Amplet2__Sip__Mos *mos) {
    printf("    Transmission Rating Factor R:%.03f\n", mos->itu_rating);
    printf("    ITU E-model MOS:%.03f\n", mos->itu_mos);
}



/*
 * Print a line for a summary statistics block.
 */
static void print_summary(char *label, Amplet2__Sip__SummaryStats *summary) {
    printf("    %s min/mean/max/sdev = %.03f/%.03f/%.03f/%.03f ms\n",
            label,
            summary->minimum / 1000.0,
            summary->mean / 1000.0,
            summary->maximum / 1000.0,
            summary->sd / 1000.0);
}



/*
 * Print information for a single direction of the RTP stream.
 */
static void print_stream(Amplet2__Sip__StreamStats *stream) {
    printf("    packets:%d bytes:%d loss:%d discard:%d reorder:%d dup:%d\n",
            stream->packets, stream->bytes, stream->lost, stream->discarded,
            stream->reordered, stream->duplicated);
    print_summary("loss period", stream->loss);
    print_summary("jitter", stream->jitter);
    print_mos(stream->mos);
}



/*
 * Print the full results for a sip test run.
 */
void print_sip(amp_test_result_t *result) {
    Amplet2__Sip__Report *msg;
    Amplet2__Sip__Header *header;
    char addrstr[INET6_ADDRSTRLEN];
    unsigned i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__sip__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->reports);

    header = msg->header;

    if ( header->has_address ) {
        inet_ntop(header->family, header->address.data, addrstr,
                INET6_ADDRSTRLEN);
    } else {
        snprintf(addrstr, INET6_ADDRSTRLEN, "unresolved %s",
                family_to_string(header->family));
    }

    printf("AMP VoIP test to %s\n", header->uri);
    printf("  Play file: %s (repeat: %s)\n", header->filename,
            header->repeat?"true":"false");
    printf("  Maximum connected duration: %d seconds\n", header->max_duration);
    printf("  Useragent: %s\n", header->useragent);
    printf("  DSCP: %s (0x%x)\n", dscp_to_str(header->dscp), header->dscp);

    for ( i = 0; i < header->n_proxy; i++ ) {
        printf("  Proxy %d: %s\n", i, header->proxy[i]);
    }

    printf("\n");
    printf("  SIP host:%s\n", header->hostname);
    printf("  RTP address:%s\n", addrstr);

    if ( msg->n_reports > 0 ) {
        Amplet2__Sip__Item *item;

        item = msg->reports[0];

        /*
         * see ETSI TS 103 222-1
         * https://www.etsi.org/deliver/etsi_ts/103200_103299/10322201/01.01.01_60/ts_10322201v010101p.pdf
         * Making the assumption that media starts immediately after ACK.
         */
        printf("\n");
        printf("  Overall connection statistics:\n");
        printf("    Time to first response: ");
        if ( item->has_time_till_first_response ) {
            printf("%.03f ms\n", item->time_till_first_response / 1000.0);
        } else {
            printf("could not connect\n");
        }

        printf("    Time to connection established: ");
        if ( item->has_time_till_connected ) {
            printf("%.03f ms\n", item->time_till_connected / 1000.0);
        } else {
            printf("could not connect\n");
        }

        printf("    Connected duration: ");
        if ( item->has_duration ) {
            printf("%.03f ms\n", item->duration / 1000.0);
        } else {
            printf("could not connect\n");
        }

        if ( item->rtt ) {
            print_summary("RTT", item->rtt);
        }

        if ( item->rx ) {
            printf("  Received:\n");
            print_stream(item->rx);
        }
        /*
         * TX loss might not be entirely accurate? If this is correct:
         * lists.pjsip.org/pipermail/pjsip_lists.pjsip.org/2009-April/007018.html
         */
        if ( item->tx ) {
            printf("  Transmitted:\n");
            print_stream(item->tx);
        }
    } else {
        printf("\n");
        printf("No test results\n");
    }

    amplet2__sip__report__free_unpacked(msg, NULL);
}



/*
 * Extract the address pointer and length from a pj_sockaddr, put them into
 * a protobuf binary data.
 */
static int copy_pj_sockaddr_to_protobuf(ProtobufCBinaryData *dst,
        const pj_sockaddr_t *src) {
    assert(dst);

    if ( src == NULL || !pj_sockaddr_has_addr(src) ) {
        dst->data = 0;
        dst->len = 0;
        return 0;
    }

    dst->data = pj_sockaddr_get_addr(src);
    dst->len = pj_sockaddr_get_addr_len(src);

    return dst->data ? 1 : 0;
}



/*
 * Construct a protocol buffer message containing the summary statistics for
 * the RTT/jitter/loss measurements.
 */
static Amplet2__Sip__SummaryStats* report_summary(pj_math_stat *stats) {
    Amplet2__Sip__SummaryStats *summary;

    summary = calloc(1, sizeof(Amplet2__Sip__SummaryStats));
    amplet2__sip__summary_stats__init(summary);

    summary->has_maximum = 1;
    summary->maximum = stats->max;
    summary->has_minimum = 1;
    summary->minimum = stats->min;
    summary->has_mean = 1;
    summary->mean = stats->mean;
    summary->has_sd = 1;
    summary->sd = pj_math_stat_get_stddev(stats);

    return summary;
}



/*
 * Construct a protocol buffer message containing Mean Opinion Score data.
 */
static Amplet2__Sip__Mos* report_mos(pjmedia_rtcp_stream_stat *stats,
        pj_math_stat *rtt) {

    Amplet2__Sip__Mos *mos;
    double rating;

    mos = calloc(1, sizeof(Amplet2__Sip__Mos));
    amplet2__sip__mos__init(mos);

    /*
     * Absolute one-way delay:
     *  Recorded in usec, halve RTT for approximation of OWD, add maximum
     *  jitter to match udpstream test (TODO other documents suggest twice
     *  the mean jitter, also adding codec/protocol delays, e.g.
     * https://www.pingman.com/kb/article/how-is-mos-calculated-in-pingplotter-pro-50.html)
     * Packet loss probability:
     *  Recorded in packets, convert to a percentage
     * Average loss length:
     *  Recorded in usec, convert to packet count, assuming 20usec intervals
     */
    rating = calculate_itu_rating(
            (rtt->mean / 2.0) + stats->jitter.max,
            stats->loss / (stats->pkt + stats->loss) * 100,
            stats->loss_period.mean / 20.0);

    mos->has_itu_rating = 1;
    mos->itu_rating = rating;
    mos->has_itu_mos = 1;
    mos->itu_mos = calculate_itu_mos(rating);

    return mos;
}



/*
 * Construct a protocol buffer message containing all the statistics for
 * a single test flow in a single direction.
 */
static Amplet2__Sip__StreamStats* report_stream(
        pjmedia_rtcp_stream_stat *stats, pj_math_stat *rtt) {
    Amplet2__Sip__StreamStats *stream;

    stream = calloc(1, sizeof(Amplet2__Sip__StreamStats));
    amplet2__sip__stream_stats__init(stream);

    stream->has_packets = 1;
    stream->packets = stats->pkt;
    stream->has_bytes = 1;
    stream->bytes = stats->bytes;
    stream->has_lost = 1;
    stream->lost = stats->loss;
    stream->has_discarded = 1;
    stream->discarded = stats->discard;
    stream->has_reordered = 1;
    stream->reordered = stats->reorder;
    stream->has_duplicated = 1;
    stream->duplicated = stats->dup;

    stream->jitter = report_summary(&stats->jitter);
    stream->loss = report_summary(&stats->loss_period);
    stream->mos = report_mos(stats, rtt);

    return stream;
}



/*
 * Construct a protocol buffer message containing all the statistics for
 * flows involved in the test to one destination.
 */
static Amplet2__Sip__Item* report_destination(struct sip_stats_t *stats) {
    Amplet2__Sip__Item *item =
        (Amplet2__Sip__Item*)malloc(sizeof(Amplet2__Sip__Item));

    amplet2__sip__item__init(item);

    if ( stats == NULL ) {
        return item;
    }

    if ( stats->response_time > 0 ) {
        item->has_time_till_first_response = 1;
        item->time_till_first_response = stats->response_time;
    }

    if ( stats->connect_time > 0 ) {
        item->has_time_till_connected = 1;
        item->time_till_connected = stats->connect_time;
    }

    if ( stats->duration > 0 ) {
        item->has_duration = 1;
        item->duration = stats->duration;
    }

    if ( stats->stream_stats ) {
        item->rtt = report_summary(&stats->stream_stats->rtcp.rtt);
        item->rx = report_stream(&stats->stream_stats->rtcp.rx,
                &stats->stream_stats->rtcp.rtt);
        item->tx = report_stream(&stats->stream_stats->rtcp.tx,
                &stats->stream_stats->rtcp.rtt);
    }

    return item;
}



/*
 * Build the complete report message from the results we have and send it
 * onwards (to either the printing function or the rabbitmq server).
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        struct opt_t *options, struct sip_stats_t *stats) {

    Amplet2__Sip__Report msg = AMPLET2__SIP__REPORT__INIT;
    Amplet2__Sip__Header header = AMPLET2__SIP__HEADER__INIT;
    Amplet2__Sip__Item **reports = NULL;
    amp_test_result_t *result;
    pj_pool_t *pool;
    unsigned i;

    result = calloc(1, sizeof(amp_test_result_t));

    pool = pjsua_pool_create("tmp-report-results", 1000, 1000);

    /* populate the header with all the test options */
    header.uri = copy_and_null_terminate(&options->uri);
    header.useragent = copy_and_null_terminate(&options->user_agent);
    header.filename = copy_and_null_terminate(&options->filename);
    header.has_max_duration = 1;
    header.max_duration = options->max_duration;
    header.has_repeat = 1;
    header.repeat = options->repeat;
    header.has_dscp = 1;
    header.dscp = options->dscp;
    header.has_family = 1;
    header.family = get_family_from_uri(pool, options->uri);
    header.hostname = get_host_from_uri(pool, options->uri);
    header.has_address = copy_pj_sockaddr_to_protobuf(&header.address,
            options->address);

    pj_pool_release(pool);

    /* multiple proxies are possible, luckily just normal char pointers */
    header.n_proxy = options->outbound_proxy_cnt;
    header.proxy = calloc(header.n_proxy, sizeof(char*));
    for ( i = 0; i < options->outbound_proxy_cnt; i++ ) {
        header.proxy[i] = copy_and_null_terminate(&options->outbound_proxy[i]);
    }

    msg.header = &header;

    if ( stats ) {
        reports = malloc(sizeof(Amplet2__Sip__Item*));
        reports[0] = report_destination(stats);

        msg.reports = reports;
        msg.n_reports = 1;

        free(stats->stream_stats);
        free(stats);
    }

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__sip__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__sip__report__pack(&msg, result->data);

    if ( reports ) {
        if ( reports[0]->rtt ) {
            free(reports[0]->rtt);
        }

        if ( reports[0]->rx ) {
            free(reports[0]->rx->jitter);
            free(reports[0]->rx->loss);
            free(reports[0]->rx->mos);
            free(reports[0]->rx);
        }

        if ( reports[0]->tx ) {
            free(reports[0]->tx->jitter);
            free(reports[0]->tx->loss);
            free(reports[0]->tx->mos);
            free(reports[0]->tx);
        }

        free(reports[0]);
        free(reports);
    }

    for ( i = 0; i < header.n_proxy; i++ ) {
        free(header.proxy[i]);
    }

    free(header.proxy);
    free(header.uri);
    free(header.useragent);
    free(header.filename);
    free(header.hostname);

    return result;
}



/*
 * Get the RTP peer address from a media stream.
 */
static pj_sockaddr* get_peer_address(pjsua_call_id call_id) {
    pj_status_t status;
    pjsua_call *call;
    pjsip_dialog *dlg;
    pj_sockaddr *address = NULL;

    status = acquire_call("collect_statistics", call_id, &call, &dlg);
    if ( status != PJ_SUCCESS ) {
        return NULL;
    }

    if ( pjsua_call_has_media(call_id) ) {
        pjmedia_transport_info tp_info;

        /* assume the first media stream is the one of interest */
        status = pjsua_call_get_med_transport_info(call_id, 0, &tp_info);

        if ( status == PJ_SUCCESS ) {
            /* save this, because the underlying memory will go away later */
            address = calloc(1, pj_sockaddr_get_len(&tp_info.src_rtp_name));
            pj_sockaddr_cp(address, &tp_info.src_rtp_name);
        }
    } else {
        Log(LOG_WARNING, "Call has no media, can't report peer information");
    }

    /* release the lock gained by acquire_call() */
    pjsip_dlg_dec_lock(dlg);

    return address;
}



/*
 * See pjsip/src/pjsua-lib/pjsua_dump.c for info on dumping stats.
 */
static struct sip_stats_t* collect_statistics(pjsua_call_id call_id) {
    pj_status_t status;
    pjsua_call *call;
    pjsip_dialog *dlg;
    struct sip_stats_t *sip_stats;

    status = acquire_call("collect_statistics", call_id, &call, &dlg);
    if ( status != PJ_SUCCESS ) {
        return NULL;
    }

    sip_stats = calloc(1, sizeof(struct sip_stats_t));

    /*
     * pj_time_val only has millisecond precision, but all the other delays
     * we measure are in microseconds, so convert these to microseconds to
     * be consistent.
     */

    /*
     * XXX initial response times look to be a bit higher than I would expect.
     * Is this an artifact of my test environment or is pjsip slow to pickup?
     */
    if ( call->res_time.sec > 0 ) {
        pj_time_val response = call->res_time;
        PJ_TIME_VAL_SUB(response, call->start_time);
        /* if response time is less than timeout, assume we got a response */
        if ( PJ_TIME_VAL_MSEC(response) < PJSIP_TD_TIMEOUT ) {
            sip_stats->response_time = PJ_TIME_VAL_MSEC(response) * 1000;
        }
    }

    if ( call->conn_time.sec > 0 ) {
        pj_time_val connect = call->conn_time;
        PJ_TIME_VAL_SUB(connect, call->start_time);
        sip_stats->connect_time = PJ_TIME_VAL_MSEC(connect) * 1000;

        if ( call->dis_time.sec > 0 ) {
            pj_time_val duration = call->dis_time;
            PJ_TIME_VAL_SUB(duration, call->conn_time);
            sip_stats->duration = PJ_TIME_VAL_MSEC(duration) * 1000;
        }
    }

    /* SIP might have worked ok, but there may not have been any RTP */
    if ( pjsua_call_has_media(call_id) ) {
        sip_stats->stream_stats = calloc(1, sizeof(pjsua_stream_stat));

        /* assume the first media stream is the one of interest */
        status = pjsua_call_get_stream_stat(call_id,0,sip_stats->stream_stats);
        if ( status != PJ_SUCCESS ) {
            free(sip_stats->stream_stats);
            sip_stats->stream_stats = NULL;
        }
    } else {
        Log(LOG_DEBUG, "Call has no media, can't report RTP statistics");
    }

    /* release the lock gained by acquire_call() */
    pjsip_dlg_dec_lock(dlg);

    return sip_stats;
}



/*
 *
 */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e) {
    pjsua_call_info call_info;
    struct opt_t *options;

    PJ_UNUSED_ARG(e);

    pjsua_call_get_info(call_id, &call_info);

    options = pjsua_acc_get_user_data(pjsua_acc_get_default());

    Log(LOG_DEBUG, "Call %d state changed: %d (%.*s)",
            call_id, call_info.state,
            (int)call_info.state_text.slen, call_info.state_text.ptr);

    switch ( call_info.state ) {
        case PJSIP_INV_STATE_CONFIRMED: {
            start_duration_timer(options->max_duration);
            break;
        }

        case PJSIP_INV_STATE_DISCONNECTED: {
            /* need to get information before the call is cleaned up */
            options->stats = collect_statistics(call_id);
            options->address = get_peer_address(call_id);
            break;
        }

        default: {
            /* do nothing */
            break;
        }
    };
}



/*
 *
 */
static amp_test_result_t* run_sip_client_loop(struct opt_t *options) {
    pjsua_call_id call_id;
    pj_status_t status;
    struct timeval start_time;

    gettimeofday(&start_time, NULL);

    /* make a call to the given uri */
    Log(LOG_DEBUG, "Making call to %*s", options->uri.slen, options->uri.ptr);

    /* disable video on this call */
    pjsua_call_setting call_settings;
    pjsua_call_setting_default(&call_settings);
    call_settings.vid_cnt = 0;

    status = pjsua_call_make_call(pjsua_acc_get_default(), &options->uri,
            &call_settings, NULL, NULL, &call_id);
    assert(call_id == 0);
    if ( status != PJ_SUCCESS ) {
        char errmsg[PJ_ERR_MSG_SIZE];
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s", errmsg);
        return NULL;
    }

    while ( pjsua_call_is_active(call_id) == PJ_TRUE ) {
        sleep(1);
    }

    return report_results(&start_time, options, options->stats);
}



/*
 *
 */
amp_test_result_t* run_sip_client(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    pj_status_t status;
    char errmsg[PJ_ERR_MSG_SIZE];
    pjsua_config cfg;
    pjsua_transport_config transport_config;
    pjsua_logging_config log_cfg;
    struct opt_t *options;
    BIO *ctrl = NULL;
    amp_test_result_t *result = NULL;

    /* set default values that can be overridden by the command line */
    pjsua_config_default(&cfg);
    cfg.cb.on_call_media_state = &on_call_media_state;
    cfg.cb.on_call_state = &on_call_state;
    cfg.max_calls = 1;

    pjsua_transport_config_default(&transport_config);

    pjsua_logging_config_default(&log_cfg);
    log_cfg.console_level = 0;

    /* minimise the data we send so it doesn't blow out the packet size */
    /* XXX is this still an issue? do I need to do all the minimisation? */
    set_use_minimal_messages();

    /* silence very noisy logging output during pjsua_create() */
    pj_log_set_level(0);

    if ( (status = pjsua_create()) != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s\n", errmsg);
        exit(EXIT_FAILURE);
    }

    options = parse_options(argc, argv);

    /* some of the options need to be given to specific configs */
    transport_config.port = options->sip_port;
    cfg.user_agent = options->user_agent;
    cfg.outbound_proxy_cnt = options->outbound_proxy_cnt;
    memcpy(cfg.outbound_proxy, options->outbound_proxy,
            sizeof(cfg.outbound_proxy));

    /* check exactly one of a URI or an AMP destination address is specified */
    if ( count > 0 && dests && options->uri.slen > 0 ) {
        Log(LOG_WARNING, "Option -u not valid when target address already set");
        exit(EXIT_FAILURE);
    }

    /*
     * If an AMP target is given instead of a URI, convert it to a URI. The
     * name has already been resolved (and may come from the local AMP
     * nametable, and not be available in DNS) so just connect to the address.
     *
     * TODO TLS will probably still need to know the canonical name so
     * that certificates can be verified.
     */
    if ( count > 0 && dests ) {
        char address[INET6_ADDRSTRLEN];
        char *uri;

        if ( dests[0]->ai_addr == NULL ) {
            /* no address for the target, but set the URI so it prints ok */
            if ( asprintf(&uri, "sip:%s", dests[0]->ai_canonname) < 0 ) {
                Log(LOG_WARNING, "Failed to create SIP URI from destination");
                exit(EXIT_FAILURE);
            }
            options->uri = pj_str(uri);
            goto end;
        }

        amp_inet_ntop(dests[0], address);

        /* ensure raw ipv6 addresses are enclosed in square brackets */
        if ( asprintf(&uri, "sip:%s%s%s",
                    dests[0]->ai_family == AF_INET6 ? "[" : "",
                    address,
                    dests[0]->ai_family == AF_INET6 ? "]" : "") < 0 ) {
            Log(LOG_WARNING, "Failed to create SIP URI from destination");
            exit(EXIT_FAILURE);
        }

        if ( pjsua_verify_sip_url(uri) != PJ_SUCCESS ) {
            Log(LOG_WARNING, "Bad URI: '%s'", uri);
            exit(EXIT_FAILURE);
        }

        options->uri = pj_str(uri);
    }

    /* by now there should be a valid URI to test */
    if ( options->uri.slen == 0 ) {
        Log(LOG_WARNING, "No URI or destination specified for sip test");
        exit(EXIT_FAILURE);
    }

    Log(LOG_DEBUG, "Initialising pjsua");

    if ( (status = pjsua_init(&cfg, &log_cfg, NULL)) != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s\n", errmsg);
        exit(EXIT_FAILURE);
    }

    status = register_transports(options, &transport_config, AMP_SIP_CLIENT);
    if ( status != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s\n", errmsg);
        pjsua_destroy();
        exit(EXIT_FAILURE);
    }

    /* use the null sound device, we don't want to actually play sound */
    Log(LOG_DEBUG, "Setting null sound device");
    pjsua_set_null_snd_dev();

    Log(LOG_DEBUG, "Starting pjsua");
    if ( (status = pjsua_start()) != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s\n", errmsg);
        pjsua_destroy();
        exit(EXIT_FAILURE);
    }

    /* set options as account user data so it's available in callbacks */
    pjsua_acc_set_user_data(pjsua_acc_get_default(), options);

    if ( count > 0 && dests && dests[0]->ai_addr != NULL && ssl_ctx ) {
        Amplet2__Measured__Response response;

        /* start the server if required (connected to an amplet) */
        if ( (ctrl=connect_control_server(
                        //dests[0], options.cport, &sockopts)) == NULL ) {
                        dests[0], options->control_port, NULL)) == NULL ) {
            Log(LOG_WARNING, "Failed to connect control server");
            goto end;
        }

        if ( start_remote_server(ctrl, AMP_TEST_SIP) < 0 ) {
            Log(LOG_WARNING, "Failed to start remote server");
            goto end;
        }

        /* make sure the server was started properly */
        if ( read_measured_response(ctrl, &response) < 0 ) {
            Log(LOG_WARNING, "Failed to read server control response");
            goto end;
        }

        /* TODO return something useful if this was remotely triggered? */
        if ( response.code != MEASURED_CONTROL_OK ) {
            Log(LOG_WARNING, "Failed to start server: %d %s", response.code,
                    response.message);
            goto end;
        }

        Log(LOG_DEBUG, "Remote server started ok");
    }

    result = run_sip_client_loop(options);

end:
    if ( ctrl ) {
        close_control_connection(ctrl);
    }

    if ( result == NULL ) {
        struct timeval start_time;
        gettimeofday(&start_time, NULL);
        Log(LOG_DEBUG, "Test failed to run, creating empty result message");
        /* no valid destination, report an empty result */
        result = report_results(&start_time, options, NULL);
    }

    if ( options->address ) {
        free(options->address);
    }
    free(options);
    pjsua_destroy();

    return result;
}
