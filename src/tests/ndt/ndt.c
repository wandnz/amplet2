/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2022 The University of Waikato, Hamilton, New Zealand.
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

/*
 * TODO: ability to force ipv4 or ipv6 only
 * TODO: work with ampnames as test destinations
 * TODO: use DNS servers from client configuration file
 * TODO: make work with lws 2.0 (bionic, stretch, buster)
 * TODO: determine exactly how buffers should be set for best performance
 */

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <libwebsockets.h>
#include <jansson.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "ndt.h"
#include "ndt.pb-c.h"
#include "locator.h"
#include "debug.h"
#include "dscp.h"
#include "usage.h"
#include "tcpinfo.h"
#include "print.h"
#include "serverlib.h"

#ifndef LCCSCF_USE_SSL
#define LCCSCF_USE_SSL 1
#endif

#define NDT_WEBSOCKET_PROTOCOL "net.measurementlab.ndt.v7"
#define NDT_DOWNLOAD_PATH "/ndt/v7/download"
#define NDT_UPLOAD_PATH "/ndt/v7/upload"

#define NDT_DEFAULT_MESSAGE_SIZE (1 << 13)
#define NDT_MAX_MESSAGE_SIZE (1 << 20)
#define NDT_MESSAGE_SCALING_FACTOR 16

#define NDT_DEFAULT_DURATION_SECONDS 10
#define NDT_MAX_DURATION_SECONDS 13
#define NDT_MAX_TEXT_MESSAGE_SIZE 4096

#define NDT_DOWNLOAD AMPLET2__NDT__ITEM__DIRECTION__DOWNLOAD
#define NDT_UPLOAD AMPLET2__NDT__ITEM__DIRECTION__UPLOAD

#define MAX_CONNECT_ATTEMPTS 3

#define JSON_INT(json, name) (json_integer_value(json_object_get(json, name)))



/*
 * NDT protocol specification:
 * https://github.com/m-lab/ndt-server/blob/master/spec/ndt7-protocol.md
 */

static struct option long_options[] = {
    {"rcvbuf", required_argument, 0, 'i'},
    {"nossl", no_argument, 0, 'n'},
    {"sndbuf", required_argument, 0, 'o'},
    {"url", required_argument, 0, 'u'},
    {"perturbate", required_argument, 0, 'p'},
    {"dscp", required_argument, 0, 'Q'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", optional_argument, 0, '4'},
    {"ipv6", optional_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {NULL, 0, 0, 0}
};

/* TODO returning non-zero from the callback doesn't always seem to help? So
 * for now, explicitly terminate the loop.
 */
static volatile int force_exit = 0;



/*
 * Extract TCP information from the JSON messages sent by the NDT server.
 */
static struct tcpinfo_result *extract_json_tcp_info(char *buf, int buflen) {
    json_auto_t *root;
    json_t *section;
    json_error_t error;
    struct tcpinfo_result *tcpinfo = NULL;

    Log(LOG_DEBUG, "Extracting tcpinfo data from results");

    if ( !buf || buflen < 1 ) {
        Log(LOG_DEBUG, "No tcpinfo data available");
        return NULL;
    }

    if ( !(root = json_loadb(buf, buflen, 0, &error)) ) {
        Log(LOG_WARNING, "error parsing tcpinfo data: line %d: %s",
                error.line, error.text);
        return NULL;
    }

    if ( !(section = json_object_get(root, "TCPInfo")) ) {
        Log(LOG_WARNING, "missing tcpinfo section");
        return NULL;
    }

    tcpinfo = malloc(sizeof(struct tcpinfo_result));

    tcpinfo->delivery_rate = JSON_INT(section, "DeliveryRate");
    tcpinfo->total_retrans = JSON_INT(section, "TotalRetrans");
    tcpinfo->rtt = JSON_INT(section, "RTT");
    tcpinfo->rttvar = JSON_INT(section, "RTTVar");
    tcpinfo->min_rtt = JSON_INT(section, "MinRTT");
    tcpinfo->busy_time = JSON_INT(section, "BusyTime");
    tcpinfo->rwnd_limited = JSON_INT(section, "RWndLimited");
    tcpinfo->sndbuf_limited = JSON_INT(section, "SndBufLimited");

    return tcpinfo;
}



/*
 * Websocket protocol callback.
 */
static int callback_ndt7(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len) {

    static void *latest = NULL;
    static int latest_len = 0;
    static unsigned char *writebuf = NULL;
    static unsigned int write_size = NDT_DEFAULT_MESSAGE_SIZE;

    switch (reason) {

        /* earliest time we can work with the created wsi */
        case LWS_CALLBACK_WSI_CREATE: {
            Log(LOG_DEBUG, "LWS_CALLBACK_WSI_CREATE");

            struct sockopt_t *sockopts = (struct sockopt_t*)user;
            int sock = lws_get_socket_fd(wsi);
            int family;
            socklen_t optlen = sizeof(family);

            /* we can modify socket options here before connecting */
            if ( getsockopt(sock, SOL_SOCKET, SO_DOMAIN, &family, &optlen) < 0 ) {
                return -1;

            }

            do_socket_setup(sock, family, sockopts);
            break;
        }

        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER");
            unsigned char **p = (unsigned char **)in;
            unsigned char *end = (*p) + len;
            const char *ua = PACKAGE_STRING;

            /* a well behaved client should identify itself appropriately */
            if ( lws_add_http_header_by_token(wsi,
                        WSI_TOKEN_HTTP_USER_AGENT,
                        (const unsigned char*)ua, (int)strlen(ua), p, end) ) {
                return -1;
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_ESTABLISHED");
            socklen_t addrlen;
            struct ndt_stats *stats;
            int sock;

            stats = (struct ndt_stats*)lws_context_user(lws_get_context(wsi));
            sock = lws_get_socket_fd(wsi);
            stats->addr = malloc(sizeof(struct sockaddr_storage));
            addrlen = sizeof(struct sockaddr_storage);

            /* get the address of the remote machine, so we can report it */
            if ( getpeername(sock, stats->addr, &addrlen) < 0 ) {
                Log(LOG_WARNING, "Failed to get remote peer: %s",
                        strerror(errno));
                return -1;
            }

            /* record the start time when the connection is established */
            if ( gettimeofday(&stats->start, NULL) != 0 ) {
                Log(LOG_ERR, "Could not gettimeofday(), aborting test");
                return -1;
            }

            /* if uploading, try to start sending data */
            if ( lws_get_protocol(wsi)->id == NDT_UPLOAD ) {
                lws_callback_on_writable(wsi);
            }

#if LWS_LIBRARY_VERSION_MAJOR >= 3
            /*
             * start a timer to make sure we don't run too long, though the
             * service loop timer should take care of this in most cases
             */
            lws_set_timer_usecs(wsi, NDT_MAX_DURATION_SECONDS * 1000000);
#endif
            break;
        }

#if LWS_LIBRARY_VERSION_MAJOR >= 3
        case LWS_CALLBACK_CLIENT_CLOSED: {
#else
        case LWS_CALLBACK_CLOSED: {
#endif
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_CLOSED");
            force_exit = 1;
            struct ndt_stats *stats =
                (struct ndt_stats*)lws_context_user(lws_get_context(wsi));

            /* record the end time when the connection is closed */
            if ( gettimeofday(&stats->end, NULL) != 0 ) {
                Log(LOG_ERR, "Could not gettimeofday(), aborting test");
                return -1;
            }

            /* once finished, get some stats */
            if ( lws_get_protocol(wsi)->id == NDT_DOWNLOAD ) {
                /* get tcpinfo from the most recent server text message */
                if ( latest && latest_len > 0 ) {
                    stats->tcpinfo = extract_json_tcp_info(
                            (char*)latest, latest_len);
                }
            } else {
                /* get tcpinfo from our own sending socket */
                stats->tcpinfo = get_tcp_info(lws_get_socket_fd(wsi));
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            //Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_RECEIVE");
            if ( lws_get_protocol(wsi)->id != NDT_DOWNLOAD ) {
                break;
            }

            /* TODO check for fragmented messages? lws_is_final_fragment() */
            int binary = lws_frame_is_binary(wsi);

            struct ndt_stats *stats =
                (struct ndt_stats*)lws_context_user(lws_get_context(wsi));

            /* count the bytes received */
            stats->bytes += len;

            /* track just the most recent message and decode it at the end */
            if ( !binary ) {
                //Log(LOG_DEBUG, "Received text message, len = %d", (int)len);
                if ( !latest ) {
                    latest = calloc(1, NDT_MAX_TEXT_MESSAGE_SIZE);
                }

                if ( (int)len < NDT_MAX_TEXT_MESSAGE_SIZE ) {
                    latest_len = (int)len;
                    memcpy(latest, in, latest_len);
                } else {
                    Log(LOG_WARNING,
                            "Text message too large, ignoring (got:%d, max:%d)",
                            len, NDT_MAX_TEXT_MESSAGE_SIZE);
                }
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            //Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_WRITEABLE");
            if ( lws_get_protocol(wsi)->id != NDT_UPLOAD ) {
                break;
            }

            /* build max message once, and adjust written length as we go */
            if ( writebuf == NULL ) {
                Log(LOG_DEBUG, "Building write buffer of %d bytes",
                        LWS_PRE + NDT_MAX_MESSAGE_SIZE);
                writebuf = malloc(LWS_PRE + NDT_MAX_MESSAGE_SIZE);
                lws_get_random(lws_get_context(wsi), writebuf,
                        LWS_PRE + NDT_MAX_MESSAGE_SIZE);
            }

            struct ndt_stats *stats =
                (struct ndt_stats*)lws_context_user(lws_get_context(wsi));

            /*
             * TODO is it worth checking lws_partial_buffered() or the
             * number of bytes written? But how would we schedule the next
             * send after deciding to back off?
             */
            lws_write(wsi, &writebuf[LWS_PRE], write_size, LWS_WRITE_BINARY);

            stats->bytes += write_size;

            /*
             * increase message size as more data is sent:
             * https://github.com/m-lab/ndt-server/blob/master/spec/ndt7-protocol.md#adapting-binary-message-size
             */
            if ( write_size < NDT_MAX_MESSAGE_SIZE &&
                    write_size < stats->bytes / NDT_MESSAGE_SCALING_FACTOR ) {
                write_size = write_size * 2;
            }

            /* try to write some more data as soon as we can */
            lws_callback_on_writable(wsi);
            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            Log(LOG_WARNING, "LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
            if ( in ) {
                Log(LOG_WARNING, "%*s", len, (char*)in);
            }
            force_exit = 1;
            break;
        }

        case LWS_CALLBACK_PROTOCOL_DESTROY:
            Log(LOG_DEBUG, "LWS_CALLBACK_PROTOCOL_DESTROY");
            break;

        case LWS_CALLBACK_WSI_DESTROY:
            Log(LOG_DEBUG, "LWS_CALLBACK_WSI_DESTROY");
            if ( latest ) {
                free(latest);
                latest = NULL;
                latest_len = 0;
            }
            if ( writebuf ) {
                free(writebuf);
                writebuf = NULL;
                write_size = 0;
            }
            break;

        case LWS_CALLBACK_RECEIVE_PONG:
            Log(LOG_DEBUG, "LWS_CALLBACK_RECEIVE_PONG");
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_RECEIVE_PONG");
            break;

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
            Log(LOG_DEBUG, "LWS_CALLBACK_WS_PEER_INITIATED_CLOSE");
            break;

#if LWS_LIBRARY_VERSION_MAJOR >= 3
        case LWS_CALLBACK_TIMER:
            Log(LOG_DEBUG, "LWS_CALLBACK_TIMER");
            force_exit = 1;
            break;
#endif

        default:
            break;
    }

    return 0;
}



/*
 *
 */
static struct decomposed_uri *parse_uri(char *urlstr) {
    struct decomposed_uri *uri = malloc(sizeof(struct decomposed_uri));
    char path[2048];
    const char *p;

    if ( lws_parse_uri(urlstr, &uri->scheme, &uri->host, &uri->port, &p) ) {
        Log(LOG_WARNING, "failed to parse url '%s'", urlstr);
        free(uri);
        return NULL;
    }

    /* add back the leading / on path that lws_parse_uri clobbers */
    path[0] = '/';
    strncpy(path + 1, p, sizeof(path) - 2);
    path[sizeof(path) - 1] = '\0';
    uri->path = strdup(path);

    Log(LOG_DEBUG, "scheme:%s address:%s port:%d path:%s", uri->scheme,
            uri->host, uri->port, uri->path);

    return uri;
}



/*
 *
 */
static struct lws_client_connect_info* build_lws_connect_info(
        struct decomposed_uri *uri, struct lws_context *context,
        struct sockopt_t *sockopts) {

    struct lws_client_connect_info *info;

    info = calloc(1, sizeof(struct lws_client_connect_info));

    info->address = uri->host;
    info->port = uri->port;
    info->path = uri->path;

    if ( strcmp(uri->scheme, "wss") == 0 ) {
        info->ssl_connection = LCCSCF_USE_SSL;
#if 0
        info->ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
        info->ssl_connection |= LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
        info->ssl_connection |= LCCSCF_ALLOW_EXPIRED;
        info->ssl_connection |= LCCSCF_ALLOW_INSECURE;
#endif
    }

    info->host = uri->host;
    info->origin = uri->host;
    info->ietf_version_or_minus_one = -1;
    info->protocol = NDT_WEBSOCKET_PROTOCOL;

    info->context = context;
    info->userdata = sockopts;

    return info;
}



/*
 *
 */
static struct lws_context_creation_info* build_lws_context_info(
        struct decomposed_uri *uri, int direction) {
    struct lws_context_creation_info *info;

    info = calloc(1, sizeof(struct lws_context_creation_info));

    struct lws_protocols *protocols = calloc(2, sizeof(struct lws_protocols));
    protocols[0].name = NDT_WEBSOCKET_PROTOCOL;
    protocols[0].callback = callback_ndt7;

    /* TODO how does this relate to rcvbuf or sndbuf? */
    /* rx_buffer_size is used for both rx and tx if tx_packet_size isn't set */
    protocols[0].rx_buffer_size = NDT_MAX_MESSAGE_SIZE * 2;
    protocols[0].id = direction;

    info->port = CONTEXT_PORT_NO_LISTEN;
    info->protocols = protocols;
    info->gid = -1;
    info->uid = -1;

#if LWS_LIBRARY_VERSION_MAJOR >= 3
    /* TODO how does this relate to rcvbuf or sndbuf? */
    info->pt_serv_buf_size = NDT_MAX_MESSAGE_SIZE * 2;
#endif

    info->vhost_name = uri->host;

    if ( strcmp(uri->scheme, "wss") == 0 ) {
        info->options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        //info.options |= LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED;
    }

    info->user = calloc(1, sizeof(struct ndt_stats));
    ((struct ndt_stats*)info->user)->direction = direction;
    ((struct ndt_stats*)info->user)->name = strdup(uri->host);

    return info;
}



/*
 * Construct a protocol buffer message containing the results for a single
 * element in the test schedule.
 */
static Amplet2__Ndt__Item* report_direction(struct ndt_stats *stats) {

    Amplet2__Ndt__Item *item =
        (Amplet2__Ndt__Item*)malloc(sizeof(Amplet2__Ndt__Item));

    /* fill the report item with results of a test */
    amplet2__ndt__item__init(item);
    item->has_direction = 1;
    item->direction = stats->direction;
    item->name = stats->name;
    item->city = stats->city;
    item->country = stats->country;

    if ( stats->addr ) {
        item->has_family = 1;
        item->family = stats->addr->sa_family;

        /* TODO copy_address_to_protobuf expects a struct addrinfo */
        switch ( stats->addr->sa_family ) {
            case AF_INET:
                item->has_address = 1;
                item->address.data =
                    (void*)&((struct sockaddr_in*)stats->addr)->sin_addr;
                item->address.len = sizeof(struct in_addr);
                break;
            case AF_INET6:
                item->has_address = 1;
                item->address.data =
                    (void*)&((struct sockaddr_in6*)stats->addr)->sin6_addr;
                item->address.len = sizeof(struct in6_addr);
                break;
            default:
                Log(LOG_WARNING, "Unknown address family %d",
                        stats->addr->sa_family);
                break;
        };
    }

    item->has_duration = 1;
    item->duration = DIFF_TV_US(stats->end, stats->start);
    item->has_bytes = 1;
    item->bytes = stats->bytes;

    /* add the tcpinfo block if there is one */
    if ( stats->tcpinfo ) {
        item->tcpinfo = calloc(1, sizeof(Amplet2__Ndt__TCPInfo));
        amplet2__ndt__tcpinfo__init(item->tcpinfo);
        item->tcpinfo->has_delivery_rate = 1;
        item->tcpinfo->delivery_rate = stats->tcpinfo->delivery_rate;
        item->tcpinfo->has_total_retrans = 1;
        item->tcpinfo->total_retrans = stats->tcpinfo->total_retrans;
        item->tcpinfo->has_rtt = 1;
        item->tcpinfo->rtt = stats->tcpinfo->rtt;
        item->tcpinfo->has_rttvar = 1;
        item->tcpinfo->rttvar = stats->tcpinfo->rttvar;
        item->tcpinfo->has_min_rtt = 1;
        item->tcpinfo->min_rtt = stats->tcpinfo->min_rtt;
        item->tcpinfo->has_busy_time = 1;
        item->tcpinfo->busy_time = stats->tcpinfo->busy_time;
        item->tcpinfo->has_rwnd_limited = 1;
        item->tcpinfo->rwnd_limited = stats->tcpinfo->rwnd_limited;
        item->tcpinfo->has_sndbuf_limited = 1;
        item->tcpinfo->sndbuf_limited = stats->tcpinfo->sndbuf_limited;
    }

    Log(LOG_DEBUG, "ndt result: %" PRIu64 " bytes in %" PRIu64 "ms to %s",
            item->bytes, item->duration / (uint64_t) 1000,
            (item->direction ==
             AMPLET2__NDT__ITEM__DIRECTION__DOWNLOAD) ? "download" : "upload");

    return item;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results.
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        struct ndt_stats *download, struct ndt_stats *upload,
        struct test_options *options, struct sockopt_t *sockopts) {

    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));
    Amplet2__Ndt__Report msg = AMPLET2__NDT__REPORT__INIT;
    Amplet2__Ndt__Header header = AMPLET2__NDT__HEADER__INIT;
    Amplet2__Ndt__Item **reports = NULL;
    unsigned int i = 0;

    /* populate the header with all the test options */
    /* TODO should I report the buffer sizes if they aren't set? */
    header.has_dscp = 1;
    header.dscp = sockopts->dscp;
    header.has_sock_rcvbuf = 1;
    header.sock_rcvbuf = sockopts->sock_rcvbuf;
    header.has_sock_sndbuf = 1;
    header.sock_sndbuf = sockopts->sock_sndbuf;
    header.url = options->urlstr;

    if ( download && upload ) {
        msg.n_reports = 2;
    } else if ( download || upload ) {
        msg.n_reports = 1;
    } else {
        //assert(0);
        msg.n_reports = 0;
    }

    Log(LOG_DEBUG, "Generating reports for %d directions", msg.n_reports);
    reports = calloc(msg.n_reports, sizeof(Amplet2__Ndt__Item*));

    if ( download ) {
        reports[i++] = report_direction(download);
    }

    if ( upload ) {
        reports[i] = report_direction(upload);
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__ndt__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__ndt__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < msg.n_reports; i++ ) {
        if ( reports[i]->tcpinfo ) {
            free(reports[i]->tcpinfo);
        }
        free(reports[i]);
    }

    free(reports);

    return result;
}



/*
 *
 */
static struct ndt_stats *run_direction(int direction, char *urlstr,
        struct sockopt_t *sockopts) {
    int attempts;
    struct ndt_stats *stats;

    struct lws *wsi_ndt = NULL;
    struct lws_context_creation_info *context_info;
    struct lws_client_connect_info *connect_info;
    struct lws_context *context;

    char *url_copy = strdup(urlstr);
    struct decomposed_uri *uri;
    if ( (uri = parse_uri(url_copy)) == NULL ) {
        Log(LOG_WARNING, "Unable to parse URI");
        return NULL;
    }

    context_info = build_lws_context_info(uri, direction);

    Log(LOG_DEBUG, "create context");
    context = lws_create_context(context_info);
    if ( context == NULL ) {
        Log(LOG_WARNING, "Creating libwebsocket context failed");
        exit(EXIT_FAILURE);
    }

    connect_info = build_lws_connect_info(uri, context, sockopts);

    attempts = 0;
    do {
        Log(LOG_DEBUG, "Connecting to %s", connect_info->address);
        wsi_ndt = lws_client_connect_via_info(connect_info);
        if ( wsi_ndt == NULL ) {
            Log(LOG_DEBUG, "Failed to connect to %s (attempt %d/%d)",
                    connect_info->address, attempts + 1, MAX_CONNECT_ATTEMPTS);
            attempts++;
            sleep(2);
        }
    } while ( wsi_ndt == NULL && attempts < MAX_CONNECT_ATTEMPTS );

    /* if we've connected, try to service the websocket and run the test */
    force_exit = 0;
    stats = lws_context_user(context);
    while ( wsi_ndt && !force_exit ) {
        /*
         * start isn't set till the websocket is fully established, which
         * might not be till after lws_service() has been called a few times
         */
        if ( timerisset(&stats->start) ) {
            struct timeval now;
            gettimeofday(&now, NULL);
            if ( S_FROM_US(DIFF_TV_US(now, stats->start)) >=
                    NDT_MAX_DURATION_SECONDS ) {
                break;
            }
        }

        lws_service(context, 0);
    }

    /* set the end time now if it isn't already, to cover odd exit cases */
    if ( timerisset(&stats->start) && !timerisset(&stats->end) ) {
        if ( gettimeofday(&stats->end, NULL) != 0 ) {
            Log(LOG_ERR, "Could not gettimeofday(), aborting test");
            return NULL;
        }
    }

    Log(LOG_DEBUG, "STATS: bytes:%d start:%d end:%d",
            stats->bytes, stats->start.tv_sec, stats->end.tv_sec);

    lws_context_destroy(context);
    free((void*)context_info->protocols);
    free(context_info);
    free(connect_info);
    free(uri);
    free(url_copy);

    return stats;
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-ndt [-hnvx] [-p perturbate] [-Q codepoint]\n"
            "               [-i recvbuf] [-o sndbuf]\n"
            "               [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
            "               -u url\n"
            "\n\n");

    /* test specific options */
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i, --rcvbuf         <bytes>   "
            "Maximum size of the receive (input) buffer\n");
    fprintf(stderr, "  -n, --nossl                    "
            "Choose unencrypted endpoint from the locator service\n");
    fprintf(stderr, "  -o, --sndbuf         <bytes>   "
            "Maximum size of the send (output) buffer\n");
    fprintf(stderr, "  -p, --perturbate     <msec>    "
            "Maximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -u, --url            <url>     "
            "Complete URL with scheme, server, protocol, etc\n");

    print_probe_usage();
    print_interface_usage();
    print_generic_usage();
}



/*
 * Main function to run the ndt test, returning a result structure that will
 * later be printed or sent across the network.
 */
amp_test_result_t* run_ndt(int argc, char *argv[],
        __attribute__((unused))int count,
        __attribute__((unused))struct addrinfo **dests) {

    int opt;
    struct timeval start_time;
    char *address_string;
    amp_test_result_t *result;

    struct test_options options;
    struct sockopt_t sockopts;

    int should_download = 1;
    int should_upload = 1;

    struct ndt_stats *download_stats = NULL;
    struct ndt_stats *upload_stats = NULL;
    struct target *targets = NULL;

    Log(LOG_DEBUG, "Starting NDT test");

    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

    /* set some sensible defaults */
    memset(&options, 0, sizeof(options));
    options.ssl = 1;

    /* TODO set some sensible values for recvbuf/sndbuf? */
    memset(&sockopts, 0, sizeof(sockopts));
    sockopts.sock_disable_nagle = 1;

    while ( (opt = getopt_long(argc, argv, "i:n:o:p:u:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4': address_string = parse_optional_argument(argv);
                      /* -4 without address is sorted at a higher level */
                      if ( address_string ) {
                          sockopts.sourcev4 =
                              get_numeric_address(address_string, NULL);
                      };
                      break;
            case '6': address_string = parse_optional_argument(argv);
                      /* -6 without address is sorted at a higher level */
                      if ( address_string ) {
                          sockopts.sourcev6 =
                              get_numeric_address(address_string, NULL);
                      };
                      break;
            case 'I': sockopts.device = optarg; break;
            case 'Q': if ( parse_dscp_value(optarg, &sockopts.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': /* option does nothing for this test */ break;
            case 'i': sockopts.sock_rcvbuf = atoi(optarg); break;
            case 'n': options.ssl = 0; break;
            case 'o': sockopts.sock_sndbuf = atoi(optarg); break;
            case 'p': options.perturbate = atoi(optarg); break;
            case 'u': options.urlstr = optarg; break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS); break;
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS); break;
            default: usage(); exit(EXIT_FAILURE); break;
	};
    }

    /* delay the start by a random amount if perturbate is set */
    if ( options.perturbate ) {
	int delay;
	delay = options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		options.perturbate, delay);
	usleep(delay);
    }

    /* TODO create a service url from a destination ampname */
    /* if the url is set then we can only test in one direction */
    if ( options.urlstr ) {
        if ( strstr(options.urlstr, NDT_DOWNLOAD_PATH) ) {
            should_download = 1;
            should_upload = 0;
        } else if ( strstr(options.urlstr, NDT_UPLOAD_PATH) ) {
            should_download = 0;
            should_upload = 1;
        } else {
            Log(LOG_WARNING, "Invalid NDT service URL");
            exit(EXIT_FAILURE);
        }
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(EXIT_FAILURE);
    }

    /* if no specific url is set, use the ndt locator service */
    if ( !options.urlstr ) {
        targets = locate();
        if ( !targets ) {
            Log(LOG_WARNING, "No targets returned by locator service");
        }
    }

    if ( targets || options.urlstr ) {
        if ( should_download ) {
            char *urlstr;
            if ( options.urlstr ) {
                urlstr = options.urlstr;
            } else {
                if ( options.ssl ) {
                    urlstr = targets[0].urls[NDT_WSS_DOWNLOAD];
                } else {
                    urlstr = targets[0].urls[NDT_WS_DOWNLOAD];
                }
            }

            Log(LOG_DEBUG, "Starting ndt download test using url %s", urlstr);
            download_stats = run_direction(NDT_DOWNLOAD, urlstr, &sockopts);

            if ( targets ) {
                download_stats->city = targets[0].city;
                download_stats->country = targets[0].country;
            }
        }

        // XXX if download failed, should we still try to upload?
        if ( should_upload ) {
            char *urlstr;
            if ( options.urlstr ) {
                urlstr = options.urlstr;
            } else {
                if ( options.ssl ) {
                    urlstr = targets[0].urls[NDT_WSS_UPLOAD];
                } else {
                    urlstr = targets[0].urls[NDT_WS_UPLOAD];
                }
            }

            Log(LOG_DEBUG, "Starting ndt upload test using url %s", urlstr);
            upload_stats = run_direction(NDT_UPLOAD, urlstr, &sockopts);

            if ( targets ) {
                upload_stats->city = targets[0].city;
                upload_stats->country = targets[0].country;
            }
        }

        // TODO free targets
    }

    /* send report */
    result = report_results(&start_time, download_stats, upload_stats,
            &options, &sockopts);

    /* tidy up after ourselves */
    if ( sockopts.sourcev4 ) {
        freeaddrinfo(sockopts.sourcev4);
    }

    if ( sockopts.sourcev6 ) {
        freeaddrinfo(sockopts.sourcev6);
    }

    if ( download_stats ) {
        if ( download_stats->tcpinfo ) free(download_stats->tcpinfo);
        if ( download_stats->addr ) free(download_stats->addr);
        if ( download_stats->name ) free(download_stats->name);
        free(download_stats);
    }

    if ( upload_stats ) {
        if ( upload_stats->tcpinfo ) free(upload_stats->tcpinfo);
        if ( upload_stats->addr ) free(upload_stats->addr);
        if ( upload_stats->name ) free(upload_stats->name);
        free(upload_stats);
    }

    return result;
}



/*
 * Print ndt test results to stdout, nicely formatted for the standalone test
 */
void print_ndt(amp_test_result_t *result) {
    Amplet2__Ndt__Report *msg;
    Amplet2__Ndt__Item *item;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__ndt__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print test header information */
    if ( msg->header->url ) {
        printf("\nAMP ndt test using endpoint %s\n", msg->header->url);
    } else {
        printf("\nAMP ndt test using the locator service\n");
    }

    printf("Options: DSCP %s (0x%0x)",
            dscp_to_str(msg->header->dscp), msg->header->dscp);

    printf(", rcvbuf: ");
    if ( msg->header->sock_rcvbuf ) {
        printf("%d", msg->header->sock_rcvbuf);
    } else {
        printf("default");
    }

    printf(", sndbuf: ");
    if ( msg->header->sock_sndbuf ) {
        printf("%d", msg->header->sock_sndbuf);
    } else {
        printf("default");
    }

    printf("\n");

    if ( msg->n_reports == 0 ) {
        printf("No result data\n");
    }

    for ( i = 0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];

        if ( item->direction == AMPLET2__NDT__ITEM__DIRECTION__DOWNLOAD ) {
            printf("  * download: ");
        } else if ( item->direction == AMPLET2__NDT__ITEM__DIRECTION__UPLOAD ) {
            printf("  * upload: ");
        } else {
            continue;
        }

        if ( !item->has_duration || !item->has_bytes ) {
            printf("test failed to run\n");
            continue;
        }

        print_formatted_bytes(item->bytes);
        printf(" in ");
        print_formatted_duration(item->duration);
        printf(" at ");
        print_formatted_speed(item->bytes, item->duration);
        printf("\n");

        printf("\tServer: %s", item->name);
        if ( item->has_address ) {
            char addrstr[INET6_ADDRSTRLEN];
            inet_ntop(item->family, item->address.data, addrstr,
                    INET6_ADDRSTRLEN);
            printf(" (%s)", addrstr);
        }
        printf("\n");

        if ( item->city || item->country ) {
            printf("\tLocation: %s, %s\n",
                    item->city ? item->city : "unknown city",
                    item->country ? item->country : "unknown country");
        }

        if ( item->tcpinfo ) {
            printf("\tTotal retransmits: %d\n",
                    item->tcpinfo->total_retrans);
            printf("\tMinimum RTT: %.02fms\n", item->tcpinfo->min_rtt / 1000.0);
            printf("\tSmoothed RTT: %.02fms +/- %.02fms\n",
                    item->tcpinfo->rtt / 1000.0,
                    item->tcpinfo->rttvar / 1000.0);
#if 0
            // TODO does delivery rate still mean what I thought it did?
            printf("\tPeak throughput: ");
            if ( item->tcpinfo->delivery_rate > 0 ) {
                printf("%.02fMbps\n",
                        item->tcpinfo->delivery_rate / 1000.0 / 1000.0 * 8);
            } else {
                printf("unavailable (delivery_rate_app_limited = 0)\n");
            }
#endif

            // TODO is this calculation still correct? Do I use busy_time right?
            if ( item->tcpinfo->rwnd_limited ) {
                printf("\tLimited by receive window %.02f%% of the test\n",
                        100.0 * item->tcpinfo->rwnd_limited /
                        item->tcpinfo->busy_time);
            }
            if ( item->tcpinfo->sndbuf_limited ) {
                printf("\tLimited by send buffer %.02f%% of the test\n",
                        100.0 * item->tcpinfo->sndbuf_limited /
                        item->tcpinfo->busy_time);
            }
        } else {
            printf("\tNo further TCP information available from sender\n");
        }
    }

    amplet2__ndt__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_NDT;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("ndt");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_ndt;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_ndt;

    /* the ndt test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the ndt test a SIGINT warning, it should not take long! */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct test_options *opt) {
    return report_results(start_time, count, info, opt);
}
#endif
