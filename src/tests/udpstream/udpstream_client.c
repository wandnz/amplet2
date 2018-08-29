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

#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#include "ssl.h"
#include "udpstream.h"
#include "testlib.h"
#include "serverlib.h"
#include "controlmsg.h"
#include "udpstream.pb-c.h"
#include "debug.h"
#include "../../measured/control.h"//XXX just for control port define
#include "dscp.h"



/*
 * Build the complete report message from the results we have and send it
 * onwards (to either the printing function or the rabbitmq server).
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        struct addrinfo *dest, struct opt_t *options,
        Amplet2__Udpstream__Item *local_report,
        Amplet2__Udpstream__Item *server_report) {

    Amplet2__Udpstream__Report msg = AMPLET2__UDPSTREAM__REPORT__INIT;
    Amplet2__Udpstream__Header header = AMPLET2__UDPSTREAM__HEADER__INIT;
    Amplet2__Udpstream__Item **reports = NULL;
    unsigned int i = 0;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    /* populate the header with all the test options */
    header.has_family = 1;
    header.family = dest->ai_family;
    header.has_packet_size = 1;
    header.packet_size = options->packet_size;
    header.has_packet_spacing = 1;
    header.packet_spacing = options->packet_spacing;
    header.has_packet_count = 1;
    header.packet_count = options->packet_count;
    header.name = address_to_name(dest);
    header.has_address = copy_address_to_protobuf(&header.address, dest);
    header.has_dscp = 1;
    header.dscp = options->dscp;
    header.has_rtt_samples = 1;
    header.rtt_samples = options->rtt_samples;

    /* only report the results that are available */
    if ( local_report && server_report ) {
        msg.n_reports = 2;
    } else if ( local_report || server_report ) {
        msg.n_reports = 1;
    } else {
        assert(0);
    }

    Log(LOG_DEBUG, "Generating reports for %d directions", msg.n_reports);
    reports = calloc(msg.n_reports, sizeof(Amplet2__Udpstream__Item*));

    if ( local_report ) {
        reports[i++] = local_report;
    }

    if ( server_report ) {
        reports[i] = server_report;
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__udpstream__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__udpstream__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    if ( local_report ) {
        amplet2__udpstream__item__free_unpacked(local_report, NULL);
    }

    if ( server_report ) {
        amplet2__udpstream__item__free_unpacked(server_report, NULL);
    }

    free(reports);

    return result;
}



/*
 * Combine RTT and VoIP results with the rest of the results. RTT results
 * are returned by the remote end so must be combined with the local results
 * before we can calculate the VoIP statistics.
 */
static Amplet2__Udpstream__Item* merge_results(ProtobufCBinaryData *data,
        struct summary_t *rtt) {

    Amplet2__Udpstream__Item *results = amplet2__udpstream__item__unpack(NULL,
            data->len, data->data);

    if ( rtt ) {
        results->rtt = report_summary(rtt);
        results->voip = report_voip(results);
    }

    return results;
}



/*
 * Unpack a protocol buffer message containing summary statistics for a test.
 */
static struct summary_t *extract_summary(ProtobufCBinaryData *data) {
    struct summary_t *stats = NULL;
    Amplet2__Udpstream__Item *item = amplet2__udpstream__item__unpack(
            NULL, data->len, data->data);

    Log(LOG_DEBUG, "Extracting rtt information from results");

    if ( item->rtt ) {
        stats = malloc(sizeof(struct summary_t));
        stats->maximum = item->rtt->maximum;
        stats->minimum = item->rtt->minimum;
        stats->mean = item->rtt->mean;
        stats->samples = item->rtt->samples;
    }

    amplet2__udpstream__item__free_unpacked(item, NULL);

    return stats;
}



/*
 * Build a simple schedule describing which way to test in which order. Based
 * loosely on the throughput test schedule building, which perhaps makes it
 * more complicated than it needs to be.
 */
static struct test_request_t* build_schedule(struct opt_t *options) {
    struct test_request_t *schedule = NULL;

    switch ( options->direction ) {
        case CLIENT_TO_SERVER:
            schedule = calloc(1, sizeof(struct test_request_t));
            schedule->direction = UDPSTREAM_TO_SERVER;
            break;

        case SERVER_TO_CLIENT:
            schedule = calloc(1, sizeof(struct test_request_t));
            schedule->direction = UDPSTREAM_TO_CLIENT;
            break;

        case SERVER_THEN_CLIENT:
            schedule = calloc(2, sizeof(struct test_request_t));
            schedule[0].direction = UDPSTREAM_TO_CLIENT;
            schedule[0].next = &schedule[1];
            schedule[1].direction = UDPSTREAM_TO_SERVER;
            break;

        case CLIENT_THEN_SERVER:
            schedule = calloc(2, sizeof(struct test_request_t));
            schedule[0].direction = UDPSTREAM_TO_SERVER;
            schedule[0].next = &schedule[1];
            schedule[1].direction = UDPSTREAM_TO_CLIENT;
            break;

        default:
            break;
    };

    return schedule;
}



/*
 * TODO could this be a library function too, with a function pointer?
 */
static amp_test_result_t* run_test(struct addrinfo *server,
        struct opt_t *options, BIO *ctrl) {

    int test_socket;
    struct sockaddr_storage ss;
    socklen_t socklen = sizeof(ss);
    struct timeval *in_times = NULL;
    struct test_request_t *schedule = NULL, *current;
    ProtobufCBinaryData data;
    Amplet2__Udpstream__Item *remote_results = NULL, *local_results = NULL;
    struct timeval start_time;
    amp_test_result_t *result;
    struct summary_t *rtt = NULL, *remote_rtt = NULL;

    /* create our test socket so it is ready early on */
    if ( (test_socket=socket(server->ai_family, SOCK_DGRAM, IPPROTO_UDP)) < 0 ){
        Log(LOG_WARNING, "Failed to create test socket:%s", strerror(errno));
        return NULL;
    }

    gettimeofday(&start_time, NULL);

    /* send hello */
    if ( send_control_hello(AMP_TEST_UDPSTREAM, ctrl,
                build_hello(options)) < 0 ) {
        Log(LOG_WARNING, "Failed to send HELLO packet, aborting");
        return NULL;
    }

    schedule = build_schedule(options);

    /* run the test schedule */
    for ( current = schedule; current != NULL; current = current->next ) {
        switch ( current->direction ) {
            case UDPSTREAM_TO_SERVER:
                if ( send_control_receive(AMP_TEST_UDPSTREAM, ctrl, NULL) < 0 ){
                    Log(LOG_WARNING, "Failed to send RECEIVE packet, aborting");
                    return NULL;
                }

                if ( read_control_ready(AMP_TEST_UDPSTREAM, ctrl,
                            &options->tport) < 0 ) {
                    Log(LOG_WARNING, "Failed to read READY packet, aborting");
                    return NULL;
                }
                ((struct sockaddr_in *)server->ai_addr)->sin_port =
                    ntohs(options->tport);

                rtt = send_udp_stream(test_socket, server, options);

                /* wait for the results from the stream we just sent */
                if ( read_control_result(AMP_TEST_UDPSTREAM, ctrl,
                            &data) < 0 ) {
                    Log(LOG_WARNING, "Failed to read RESULT packet, aborting");
                    return NULL;
                }

                Log(LOG_DEBUG, "Merging local RTT calculations with results");
                remote_results = merge_results(&data, rtt);
                free(data.data);
                free(rtt);
                break;

            case UDPSTREAM_TO_CLIENT:
                in_times = calloc(options->packet_count,sizeof(struct timeval));
                /* bind test socket to same address as the control socket */
                getsockname(BIO_get_fd(ctrl, NULL), (struct sockaddr *)&ss,
                        &socklen);
                /* zero the port so it isn't the same as the control socket */
                ((struct sockaddr_in *)&ss)->sin_port = 0;
                bind(test_socket, (struct sockaddr *)&ss, socklen);
                /* get the local port number so we can tell the remote host */
                getsockname(test_socket, (struct sockaddr *)&ss, &socklen);
                options->tport = ntohs(((struct sockaddr_in *)&ss)->sin_port);

                send_control_send(AMP_TEST_UDPSTREAM, ctrl,
                        build_send(options));

                /* wait for the data stream from the server */
                receive_udp_stream(test_socket, options, in_times);

                /* wait for the rtt for the stream we just sent */
                if ( read_control_result(AMP_TEST_UDPSTREAM, ctrl,
                            &data) < 0 ) {
                    Log(LOG_WARNING, "Failed to read RESULT packet, aborting");
                    return NULL;
                }
                Log(LOG_DEBUG, "Merging remote RTT calculations with results");
                remote_rtt = extract_summary(&data);
                local_results = report_stream(UDPSTREAM_TO_CLIENT, remote_rtt,
                        in_times, options);
                free(data.data);
                free(remote_rtt);
                break;
        };
    }

    close(test_socket);

    /* report results */
    result = report_results(&start_time, server, options, local_results,
            remote_results);

    /* TODO should these be freed here or in report_results? */
    if ( in_times ) {
        free(in_times);
    }

    free(schedule);

    return result;
}



/*
 * The main function of the udpstream client test.
 */
amp_test_result_t* run_udpstream_client(int argc, char *argv[], int count,
        struct addrinfo **dests) {

    int opt;
    struct opt_t test_options;
    struct sockopt_t sockopts;
    char *client;
    extern struct option long_options[];
    amp_test_result_t *result;
    BIO *ctrl;
    char *address_string;
    int forcev4 = 0;
    int forcev6 = 0;

    /* set some sensible defaults */
    memset(&sockopts, 0, sizeof(sockopts));
    test_options.dscp = DEFAULT_DSCP_VALUE;
    test_options.packet_spacing = DEFAULT_UDPSTREAM_INTER_PACKET_DELAY;
    test_options.packet_size = DEFAULT_UDPSTREAM_PACKET_LENGTH;
    test_options.packet_count = DEFAULT_UDPSTREAM_PACKET_COUNT;
    test_options.percentile_count = DEFAULT_UDPSTREAM_PERCENTILE_COUNT;
    test_options.cport = 0;
    test_options.tport = DEFAULT_TEST_PORT;
    //test_options.perturbate = 0;
    test_options.direction = CLIENT_THEN_SERVER;
    test_options.rtt_samples = DEFAULT_UDPSTREAM_RTT_SAMPLES;

    client = NULL;

    while ( (opt = getopt_long(argc, argv, "c:d:D:p:P:r:n:z:I:Q:Z:4::6::hx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4': forcev4 = 1;
                      address_string = parse_optional_argument(argv);
                      if ( address_string ) {
                          sockopts.sourcev4 =
                              get_numeric_address(address_string, NULL);
                      }
                      break;
            case '6': forcev6 = 1;
                      address_string = parse_optional_argument(argv);
                      if ( address_string ) {
                          sockopts.sourcev6 =
                              get_numeric_address(address_string, NULL);
                      }
                      break;
            case 'I': sockopts.device = optarg; break;
            case 'Q': if ( parse_dscp_value(optarg, &test_options.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': /* not used, but might be set globally */ break;
            case 'c': client = optarg; break;
            case 'd': test_options.direction = atoi(optarg); break;
            case 'D': test_options.packet_spacing = atoi(optarg); break;
            case 'p': test_options.cport = atoi(optarg); break;
            case 'P': test_options.tport = atoi(optarg); break;
            case 'r': test_options.rtt_samples = atoi(optarg); break;
            case 'n': test_options.packet_count = atoi(optarg); break;
            case 'z': test_options.packet_size = atoi(optarg); break;
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
	};
    }

    /*
     * Don't do anything if the test provides a target through the dests
     * parameter as well as using -c. They expect the server to behave slightly
     * differently, so we can't tell which the user wants.
     */
    if ( dests && client ) {
        Log(LOG_WARNING, "Option -c not valid when target address already set");
        exit(EXIT_FAILURE);
    }

    //XXX move into common/serverlib.c? use for throughput too
    /*
     * If the -c option is set then get the address into the dests parameter.
     * This implies that the test is running standalone, and the server will
     * already be running.
     */
    if ( client ) {
        int res;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        if ( forcev4 && !forcev6 ) {
            hints.ai_family = AF_INET;
        } else if ( forcev6 && !forcev4 ) {
            hints.ai_family = AF_INET6;
        } else {
            hints.ai_family = AF_UNSPEC;
        }
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        dests = (struct addrinfo **)malloc(sizeof(struct addrinfo *));
        if ( (res = getaddrinfo(client, NULL, &hints, &dests[0])) < 0 ) {
            Log(LOG_WARNING, "Failed to resolve '%s': %s", client,
                    gai_strerror(res));
            exit(EXIT_FAILURE);
        }

        /* just take the first address we find */
        /* TODO retry with the next address if one fails */
        count = 1;

        /* set the canonical name to be the address so we can print it later */
        dests[0]->ai_canonname = strdup(client);

        /* use the udpstream control port, rather than the amplet2 one */
        if ( test_options.cport == 0 ) {
            test_options.cport = DEFAULT_CONTROL_PORT;
        }
    } else {
        /* use the amplet2 control port, rather than the udpstream one */
        if ( test_options.cport == 0 ) {
            test_options.cport = atoi(DEFAULT_AMPLET_CONTROL_PORT);
        }
    }

    /*
     * Make sure we got a destination, either through the dests parameter
     * or the -c command line argument
     */
    if ( count < 1 || dests == NULL || dests[0] == NULL ) {
        Log(LOG_WARNING, "No destination specified for throughput test");
        exit(EXIT_FAILURE);
    }

    /* make sure that we are sending enough packets to do something useful */
    if ( test_options.packet_count < MINIMUM_UDPSTREAM_PACKET_COUNT ) {
        Log(LOG_WARNING, "Packet count %d below minimum, raising to %d",
                test_options.packet_count, MINIMUM_UDPSTREAM_PACKET_COUNT);
        test_options.packet_count = MINIMUM_UDPSTREAM_PACKET_COUNT;
    }

    /* make sure that the packet size is big enough for our data */
    if ( test_options.packet_size < MINIMUM_UDPSTREAM_PACKET_LENGTH ) {
	Log(LOG_WARNING, "Packet size %d below minimum, raising to %d",
		test_options.packet_size, MINIMUM_UDPSTREAM_PACKET_LENGTH);
	test_options.packet_size = MINIMUM_UDPSTREAM_PACKET_LENGTH;
    }

    /* make sure that the packet size isn't too big either */
    if ( test_options.packet_size > MAXIMUM_UDPSTREAM_PACKET_LENGTH ) {
	Log(LOG_WARNING, "Packet size %d above maximum, lowering to %d",
		test_options.packet_size, MAXIMUM_UDPSTREAM_PACKET_LENGTH);
	test_options.packet_size = MAXIMUM_UDPSTREAM_PACKET_LENGTH;
    }

    /* make sure we are sampling a vaguely sensible number of rtt packets */
    if ( test_options.rtt_samples > test_options.packet_count ) {
	Log(LOG_WARNING, "RTT samples %d above packet count, clamping to %d",
		test_options.rtt_samples, test_options.packet_count);
	test_options.rtt_samples = test_options.packet_count;
    }

#if 0
    /* delay the start by a random amount of perturbate is set */
    if ( test_options.perturbate ) {
	int delay;
	delay = test_options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		test_options.perturbate, delay);
	usleep(delay);
    }
#endif

    /* connect to the control server to start/configure the test */
    if ( (ctrl=connect_control_server(
                    dests[0], test_options.cport, &sockopts)) == NULL ) {
        Log(LOG_WARNING, "Failed to connect control server");
        return NULL;
    }

    /* start the server if required (connected to an amplet) */
    if ( ssl_ctx && client == NULL ) {
        Amplet2__Measured__Response response;

        if ( start_remote_server(ctrl, AMP_TEST_UDPSTREAM) < 0 ) {
            Log(LOG_WARNING, "Failed to start remote server");
            return NULL;
        }

        /* make sure the server was started properly */
        if ( read_measured_response(ctrl, &response) < 0 ) {
            Log(LOG_WARNING, "Failed to read server control response");
            return NULL;
        }

        /* TODO return something useful if this was remotely triggered? */
        if ( response.code != MEASURED_CONTROL_OK ) {
            Log(LOG_WARNING, "Failed to start server: %d %s", response.code,
                    response.message);
            return NULL;
        }
    }

    result = run_test(dests[0], &test_options, ctrl);

    close_control_connection(ctrl);

    if ( client != NULL ) {
        freeaddrinfo(dests[0]);
        free(dests);
    }

    if ( sockopts.sourcev4 ) {
        freeaddrinfo(sockopts.sourcev4);
    }

    if ( sockopts.sourcev6 ) {
        freeaddrinfo(sockopts.sourcev6);
    }

    return result;
}



/*
 * Print the results for a single test direction.
 */
static void print_item(Amplet2__Udpstream__Item *item, uint32_t packet_count) {
    uint32_t i;

    assert(item);

    if ( item->direction ==
            AMPLET2__UDPSTREAM__ITEM__DIRECTION__SERVER_TO_CLIENT ) {
        printf("  * server -> client\n");
    } else if ( item->direction ==
            AMPLET2__UDPSTREAM__ITEM__DIRECTION__CLIENT_TO_SERVER ) {
        printf("  * client -> server\n");
    } else {
        return;
    }

    printf("      %d packets transmitted, %d received, %.02f%% packet loss\n",
            packet_count, item->packets_received,
            100 - ((double)item->packets_received / (double)packet_count*100));

    if ( item->rtt ) {
        printf("      %d rtt samples min/mean/max = %.03f/%.03f/%.03f ms\n",
                item->rtt->samples, item->rtt->minimum/1000.0,
                item->rtt->mean/1000.0, item->rtt->maximum/1000.0);
    } else {
        printf("      no rtt information available\n");
    }

    if ( item->jitter ) {
        printf("      %d jitter samples min/mean/max = %.03f/%.03f/%.03f ms\n",
                item->jitter->samples, item->jitter->minimum/1000.0,
                item->jitter->mean/1000.0, item->jitter->maximum/1000.0);
    } else {
        printf("      no jitter information available\n");
    }

    printf("      percentiles:\n");
    for ( i = 0; i < item->n_percentiles; i++ ) {
        printf("        %3d: %+.03f ms\n", (i+1) * 10,
                item->percentiles[i]/1000.0);
    }

    printf("      arrival patterns:");
    for ( i = 0; i < item->n_loss_periods; i++ ) {
        printf(" %d %s", item->loss_periods[i]->length,
                item->loss_periods[i]->status ? "ok" : "lost");
    }
    printf("\n");

    if ( item->voip ) {
        printf("      Voice Score Values (assuming G.711 codec):\n");
        printf("        Calculated Planning Impairment Factor (ICPIF): %d\n",
                item->voip->icpif);
        printf("        Cisco MOS: %.02f\n", item->voip->cisco_mos);
        printf("        Transmission Rating Factor R: %.02f\n",
                item->voip->itu_rating);
        printf("        ITU E-model MOS: %.02f\n", item->voip->itu_mos);
    } else {
        printf("      no voip information available\n");
    }
}



/*
 * Print the full results for a test run.
 */
void print_udpstream(amp_test_result_t *result) {
    Amplet2__Udpstream__Report *msg;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__udpstream__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print global configuration options */
    printf("\n");
    inet_ntop(msg->header->family, msg->header->address.data, addrstr,
            INET6_ADDRSTRLEN);
    printf("AMP udpstream test to %s (%s)\n", msg->header->name, addrstr);
    printf("packet count:%" PRIu32 ", size:%" PRIu32 " bytes, spacing:%" PRIu32
            "us, DSCP:%s(0x%x)\n",
            msg->header->packet_count, msg->header->packet_size,
            msg->header->packet_spacing, dscp_to_str(msg->header->dscp),
            msg->header->dscp);

    /* print the individual test runs in each direction */
    for ( i=0; i < msg->n_reports; i++ ) {
        print_item(msg->reports[i], msg->header->packet_count);
    }

    amplet2__udpstream__report__free_unpacked(msg, NULL);
}
