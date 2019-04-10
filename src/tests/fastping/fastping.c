/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Jayden Hewer
 *         Brendon Jones
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
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <math.h>
#include <inttypes.h>

#include "config.h"
#include "tests.h"
#include "debug.h"
#include "testlib.h"
#include "fastping.pb-c.h"
#include "fastping.h"
#include "usage.h"
#include "dscp.h"
#include "checksum.h"



static struct option long_options[] = {
    {"count", required_argument, 0, 'c'},
    {"size", required_argument, 0, 's'},
    {"rate", required_argument, 0, 'r'},
    {"preemptive", no_argument, 0, 'p'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", required_argument, 0, '4'},
    {"ipv6", required_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {"dscp", required_argument, 0, 'Q'},
    {NULL, 0, 0, 0}
};



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-fastping [-hpvx] [-c count] [-r rate] [-s size] "
            "-- destination\n\n");
    fprintf(stderr, "  -c, --count          <packets> "
            "Number of packets to be sent during the test\n");
    fprintf(stderr, "  -p, --preemptive               "
            "Send initial packets to prime stateful devices\n");
    fprintf(stderr, "  -s, --size           <bytes>   "
            "Packet size to use for the test\n");
    fprintf(stderr, "  -r, --rate           <pps>     "
            "Number of packets per second to send\n");

    print_probe_usage();
    print_interface_usage();
    print_generic_usage();
}



/*
 * Sort function used to order packets for percentile calculations
 */
static int cmp (const void *a, const void *b) {
    return ( *(int32_t*)a - *(int32_t*)b );
}



/*
 * Construct a protocol buffer message containing the summary statistics for
 * the RTT or jitter measurements.
 */
static Amplet2__Fastping__SummaryStats* report_summary(
        struct summary_t *summary, int32_t *ipv) {
    Amplet2__Fastping__SummaryStats *stats;
    int i;

    if ( !summary || !ipv ) {
        return NULL;
    }

    stats = calloc(1, sizeof(Amplet2__Fastping__SummaryStats));
    amplet2__fastping__summary_stats__init(stats);

    stats->has_maximum = 1;
    stats->maximum = summary->maximum;
    stats->has_minimum = 1;
    stats->minimum = summary->minimum;
    stats->has_mean = 1;
    stats->mean = (uint32_t)round(summary->mean);
    stats->has_sd = 1;
    stats->sd = summary->sd;
    stats->has_samples = 1;
    stats->samples = summary->samples;

    stats->n_percentiles = PERCENTILE_COUNT;
    stats->percentiles = calloc(stats->n_percentiles, sizeof(int32_t));

    for ( i = 0; i < PERCENTILE_COUNT; i++ ) {
        uint32_t index = PERCENTILES[i] / 100 * summary->samples;
        if ( index >= summary->samples ) {
            index--;
        }
        stats->percentiles[i] = ipv[index];
        Log(LOG_DEBUG, "Percentile %.02f: %d\n", PERCENTILES[i], ipv[index]);
    }

    return stats;
}



/*
 * Construct a protocol buffer message containing all the statistics for
 * a single test flow, including packet interarrivals, RTT measurements,
 * etc.
 */
static Amplet2__Fastping__Item* report_destination(struct info_t *timing,
        struct opt_t *options, struct timeval *runtime) {

    Amplet2__Fastping__Item *item =
        (Amplet2__Fastping__Item*)malloc(sizeof(Amplet2__Fastping__Item));
    uint64_t i;
    uint64_t current = 0, prev = 0;
    struct timeval latency;
    double delta, delta2;
    double rtt_squares, jitter_squares;
    int32_t *ipv;
    int32_t *ipdv;
    struct summary_t rtt, jitter;

    amplet2__fastping__item__init(item);

    memset(&rtt, 0, sizeof(rtt));
    memset(&jitter, 0, sizeof(jitter));

    ipv = calloc(options->count, sizeof(int32_t));
    ipdv = calloc(options->count, sizeof(int32_t));

    rtt_squares = 0;
    jitter_squares = 0;

    for ( i = 0; i < options->count; i++ ) {
        if ( !timerisset(&timing[i].time_received) ) {
            continue;
        }

        timersub(&timing[i].time_received, &timing[i].time_sent, &latency);
        current = (latency.tv_sec * 1000000) + latency.tv_usec;

        ipv[rtt.samples] = current;
        delta = (double)current - rtt.mean;
        rtt.samples++;
        rtt.mean += delta / rtt.samples;
        delta2 = (double)current - rtt.mean;
        rtt_squares += (delta * delta2);

        if ( rtt.samples > 1 ) {
            ipdv[jitter.samples] = current - prev;
            delta = (double)current - (double)prev - jitter.mean;
            jitter.samples++;
            jitter.mean += delta / jitter.samples;
            delta2 = (double)current - (double)prev - jitter.mean;
            jitter_squares += (delta * delta2);
        }

        prev = current;
    }

    if ( rtt.samples > 0 ) {
        qsort(ipv, rtt.samples, sizeof(int32_t), cmp);
        rtt.maximum = ipv[rtt.samples - 1];
        rtt.minimum = ipv[0];
        rtt.sd = sqrt(rtt_squares / rtt.samples);
        item->rtt = report_summary(&rtt, ipv);
    }

    if ( jitter.samples > 0 ) {
        qsort(ipdv, jitter.samples, sizeof(int32_t), cmp);
        jitter.maximum = ipdv[jitter.samples - 1];
        jitter.minimum = ipdv[0];
        jitter.sd = sqrt(jitter_squares / jitter.samples);
        item->jitter = report_summary(&jitter, ipdv);
    }

    item->has_runtime = 1;
    item->runtime = runtime->tv_sec * 1000000 + runtime->tv_usec;

    free(ipv);
    free(ipdv);

    return item;
}



/*
 * Build the protocol buffer message containing the result.
 */
static amp_test_result_t* report_result(struct timeval *start_time,
        struct addrinfo *dest, struct opt_t *options, struct info_t *timing,
        struct timeval *runtime) {

    int count = 1;

    Log(LOG_DEBUG, "Reporting fastping results");

    Amplet2__Fastping__Report msg = AMPLET2__FASTPING__REPORT__INIT;
    Amplet2__Fastping__Header header = AMPLET2__FASTPING__HEADER__INIT;
    Amplet2__Fastping__Item **reports = NULL;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    header.has_address = copy_address_to_protobuf(&header.address, dest);
    header.has_family = 1;
    header.family = dest->ai_family;
    header.name = address_to_name(dest);
    header.has_count = 1;
    header.count = options->count;
    header.has_rate = 1;
    header.rate = options->rate;
    header.has_size = 1;
    header.size = options->size;
    header.has_preprobe = 1;
    header.preprobe = options->preemptive;
    header.has_dscp = 1;
    header.dscp = options->dscp;

    reports = malloc(sizeof(Amplet2__Fastping__Item*) * count);
    reports[0] = report_destination(timing, options, runtime);

    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = count;

    /* pack all the results into a buffer for transmission */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__fastping__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__fastping__report__pack(&msg, result->data);

    /* free all data that is no longer required by the protobuffer */
    free(reports[0]->rtt);
    free(reports[0]->jitter);
    free(reports[0]);
    free(reports);

    return result;
}



/*
 * Open the raw ICMP and ICMPv6 sockets used for this test and configure
 * appropriate filters for the ICMPv6 socket to only receive echo replies.
 */
static int open_sockets(struct socket_t *sockets) {
    if ( (sockets->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMP");
    }

    if ( (sockets->socket6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMPv6");
    } else {
	/* configure ICMPv6 filters to only pass through ICMPv6 echo reply */
	struct icmp6_filter filter;
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
	if ( setsockopt(sockets->socket6, SOL_ICMPV6, ICMP6_FILTER,
		    &filter, sizeof(struct icmp6_filter)) < 0 ) {
	    Log(LOG_WARNING, "Could not set ICMPv6 filter");
	}
    }

    /* make sure at least one type of socket is opened */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
        return -1;
    }

    return 0;
}



/*
 * Open and configure the test sockets then bind them to interfaces/devices.
 */
static int configure_socket(struct socket_t *sockets, struct opt_t *options,
        char *device, struct addrinfo *sourcev4, struct addrinfo *sourcev6) {

    if ( open_sockets(sockets) < 0 ) {
        Log(LOG_ERR, "Unable to open raw ICMP sockets, aborting test");
        return -1;
    }

    if ( set_default_socket_options(sockets) < 0 ) {
        Log(LOG_ERR, "Failed to set default socket options, aborting test");
        return -1;
    }

    if ( set_dscp_socket_options(sockets, options->dscp) < 0 ){
        Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
        return -1;
    }

    if ( device && bind_sockets_to_device(sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw ICMP socket to device, aborting test");
        return -1;
    }

    if ( (sourcev4 || sourcev6) &&
            bind_sockets_to_address(sockets, sourcev4, sourcev6) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw ICMP socket to address, aborting test");
        return -1;
    }

    return 0;
}



/*
 * Create the packet and fill in the required fields. The ICMP header only
 * has 16 bits for sequence numbers, so include a 64 bit field to track
 * the actual value for use once the sequence wraps. The two fields are
 * separate arguments so that they can be set to different values if desired
 * (to cause the response packets to fail sanity checking and be ignored).
 */
static int build_packet(uint8_t family, void *packet, uint16_t size,
        uint16_t seq, uint16_t ident, uint64_t magic) {

    struct icmphdr *icmp;
    int hlen;

    assert(packet);
    assert(size >= MINIMUM_FASTPING_PACKET_SIZE);

    memset(packet, 0, size);

    icmp = (struct icmphdr*)packet;
    icmp->type = (family == AF_INET) ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(ident);
    icmp->un.echo.sequence = ntohs(seq);
    memcpy((uint8_t *)packet + sizeof(struct icmphdr), &magic, sizeof(magic));

    if ( family == AF_INET ) {
        hlen = sizeof(struct iphdr);
        icmp->checksum = checksum((uint16_t*)packet, size - hlen);
    } else {
        hlen = sizeof(struct ip6_hdr);
        /* icmp6 checksum will be calculated for us */
    }

    return size - hlen;
}



/*
 * Determine if the packet is a response to one we've sent, and if so extract
 * the full length sequence number from it.
 */
static int64_t extract_data(struct addrinfo *dest, char *packet,
        uint16_t ident, struct sockaddr *from) {

    int64_t magic = 0;
    uint16_t sequence = 0;
    size_t sockaddrlen;

    ident = ntohs(ident);

    if ( dest->ai_family == AF_INET ) {
        struct iphdr* ip = (struct iphdr*) packet;
        struct icmphdr *icmp = (struct icmphdr*)(packet + (ip->ihl * 4));

        if ( icmp->type != ICMP_ECHOREPLY || icmp->un.echo.id != ident ) {
            return -1;
        }

        sequence = icmp->un.echo.sequence;
        sockaddrlen = sizeof(struct sockaddr_in);
    } else {
        struct icmp6_hdr *icmp = (struct icmp6_hdr*)packet;

        if ( icmp->icmp6_type != ICMP6_ECHO_REPLY || icmp->icmp6_id != ident ) {
            return -1;
        }

        sequence = icmp->icmp6_seq;
        sockaddrlen = sizeof(struct sockaddr_in6);
    }

    /* doesn't hurt to check that the address matches what we expect */
    if ( memcmp(dest->ai_addr, from, sockaddrlen) != 0 ) {
        return -1;
    }

    /* extract the full 64 bit sequence value from the packet payload */
    magic = *(int64_t*)(((char *)packet) + sizeof(struct icmphdr));

    /* the last 16 bits should match the ICMP sequence number */
    if ( ( (uint16_t) magic) != ntohs(sequence)) {
        return -1;
    }

    return magic;
}



/*
 * Build, send and receive the packets for the test. Rather than using
 * libwandevent we instead loop tightly around select() with a zero timeout
 * to try to minimise delay between when a packet should be sent, and when it
 * is sent.
 */
static amp_test_result_t* send_icmp_stream(struct addrinfo *dest,
        struct socket_t *sockets, struct opt_t *options) {

    char *packet;
    int length;
    char response[RESPONSE_BUFFER_LEN];
    struct info_t *timing;

    struct timeval run_time;
    struct timeval start_time;
    struct timeval stop_time;
    struct timeval next_packet;
    struct timeval interpacket_gap;
    struct timeval loss_timeout;

    struct sockaddr from;
    amp_test_result_t *results;

    uint64_t sent = 0;
    uint64_t received = 0;
    uint16_t pid = getpid();
    int sock;

    memset(&stop_time, 0, sizeof(struct timeval));
    memset(&loss_timeout, 0, sizeof(struct timeval));

    /* extract the socket depending on the address family */
    switch ( dest->ai_family ) {
        case AF_INET: sock = sockets->socket; break;
        case AF_INET6: sock = sockets->socket6; break;
        default:
           Log(LOG_ERR,"Unknown address family %d", dest->ai_family);
           return NULL;
    };

    /* packet rate is an integer above zero, so longest gap is only 1 second */
    interpacket_gap.tv_sec = options->rate <= 1 ? 1 : 0;
    interpacket_gap.tv_usec = options->rate > 1 ? (1000000 / options->rate) : 0;

    timing = calloc(options->count, sizeof(struct info_t));
    packet = calloc(1, options->size);

    /* try to prime any stateful devices that might be in the path */
    if ( options->preemptive ) {
        Log(LOG_DEBUG, "Sending 3 packets to prime devices in the path");
        /* sequence and magic fields are different so we can filter these out */
        length = build_packet(dest->ai_family, packet, options->size,
                UINT16_MAX, pid, 0);
        /* arbitrarily, send 3 packets in the hopes at least one will arrive */
        delay_send_packet(sock, packet, length, dest, 0, NULL);
        delay_send_packet(sock, packet, length, dest, 0, NULL);
        delay_send_packet(sock, packet, length, dest, 0, NULL);
        /* arbitrarily, sleep briefly to allow creation of state in devices */
        usleep(500000);
    }

    Log(LOG_DEBUG, "Starting packet stream");

    /* generate the first packet of the run before we are ready to send it */
    length = build_packet(dest->ai_family, packet, options->size, 0, pid, 0);

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(EXIT_FAILURE);
    }

    timeradd(&start_time, &interpacket_gap, &next_packet);

    while ( sent < options->count || received < options->count ) {
        struct timeval timeout;
        struct timeval now;
        fd_set readfds, writefds;

        if ( sent < options->count ) {
            /* don't let select sleep while we have packets still to send */
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            /* otherwise we'll wait for a bit after the last packet we saw */
            timeout.tv_sec = FASTPING_PACKET_LOSS_TIMEOUT;
            timeout.tv_usec = 0;
        }

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        FD_SET(sock, &writefds);
        FD_SET(sock, &readfds);

        if ( select(sock+1, &readfds, &writefds, NULL, &timeout) < 0 ) {
            if ( errno == EINTR ) {
                continue;
            }
            Log(LOG_ERR, "Select failed");
            return NULL;
        }

        /* get the current time to use to see if a packet should be sent */
        gettimeofday(&now, NULL);

        if ( sent < options->count && !timercmp(&now, &next_packet, <) ) {
            if ( FD_ISSET(sock, &writefds) ) {
                delay_send_packet(sock, packet, length, dest, 0,
                        &(timing[sent].time_sent));

                timeradd(&next_packet, &interpacket_gap, &next_packet);
                sent++;

                /* generate the next packet so it is ready when the socket is */
                build_packet(dest->ai_family, packet, options->size, sent, pid,
                        sent);
            } else {
                /* if it's time to send but the socket was busy, try again */
                continue;
            }
        }

        /* if all the packets have been sent, start the timer to wait */
        if ( sent >= options->count ) {
            if ( stop_time.tv_sec == 0 && stop_time.tv_usec == 0 ) {
                struct timeval temp;
                gettimeofday(&stop_time, NULL);
                temp.tv_sec = FASTPING_PACKET_LOSS_TIMEOUT;
                temp.tv_usec = 0;
                timeradd(&stop_time, &temp, &loss_timeout);
                Log(LOG_DEBUG, "Finished packet stream");
            } else {
                /* check if its time to timeout and declare packets lost */
                if ( !timercmp(&now, &loss_timeout, <) ) {
                    Log(LOG_DEBUG, "Timed out waiting for responses");
                    break;
                }
            }
        }

        /* check to see if there is data in the socket waiting to be read */
        if ( FD_ISSET(sock, &readfds) ) {
            int wait = 0;
            int bytes;
            struct timeval receive_time;

            /* read one packet out of the buffer for processing */
            bytes = get_packet(sockets, response, RESPONSE_BUFFER_LEN, &from,
                    &wait, &receive_time);

            if ( bytes > 0 ) {
                /* extract the sequence number from the icmp packet */
                int64_t sequence = extract_data(dest, response, pid, &from);
                if ( sequence >= 0 && sequence < options->count) {
                    memcpy(&(timing[sequence].time_received),
                            &receive_time, sizeof(struct timeval));
                    received++;
                    if ( received >= options->count ) {
                        Log(LOG_DEBUG, "Received all responses");
                        break;
                    }
                }
            }
        }
    }

    Log(LOG_DEBUG, "Calculating fastping results");

    timersub(&stop_time, &start_time, &run_time);

    results = report_result(&start_time, dest, options, timing, &run_time);

    free(timing);
    free(packet);

    return results;
}



/*
 * Main function to run the fastping test, returning a result structure that
 * will later be printed or sent across the network.
 */
amp_test_result_t* run_fastping(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    char *address_string;
    struct opt_t options;
    struct socket_t sockets;

    /* set some sensible defaults */
    options.count = DEFAULT_FASTPING_PACKET_COUNT;
    options.rate = DEFAULT_FASTPING_PACKET_RATE;
    options.size = DEFAULT_FASTPING_PACKET_SIZE;
    options.preemptive = 0;
    options.dscp = DEFAULT_DSCP_VALUE;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "c:s:r:phxv4::6::I:Q:Z:",
             long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4': address_string = parse_optional_argument(argv);
                      /* -4 without address is sorted at a higher level */
                      if ( address_string ) {
                          sourcev4 = get_numeric_address(address_string, NULL);
                      };
                      break;
            case '6': address_string = parse_optional_argument(argv);
                      /* -6 without address is sorted at a higher level */
                      if ( address_string ) {
                          sourcev6 = get_numeric_address(address_string, NULL);
                      };
                      break;
            case 'I': device = optarg; break;
            case 'Q': if ( parse_dscp_value(optarg, &options.dscp) < 0 ) {
                        Log(LOG_WARNING, "Invalid DSCP value, aborting");
                        exit(-1);
                      }
                      break;
            case 'Z': /* option does nothing for this test */ break;
            case 'c': options.count = atoi(optarg); break;
            case 's': options.size = atoi(optarg); break;
            case 'r': options.rate = atoi(optarg); break;
            case 'p': options.preemptive = 1; break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( count < 1 || dests == NULL || dests[0] == NULL ) {
        Log(LOG_WARNING, "No destination specified for fastping test");
        exit(EXIT_FAILURE);
    }

    if ( options.rate < 1 || options.rate > MAXIMUM_FASTPING_PACKET_RATE ) {
        Log(LOG_INFO, "Setting packet rate to maximum value %d\n",
                MAXIMUM_FASTPING_PACKET_RATE);
        options.rate = MAXIMUM_FASTPING_PACKET_RATE;
    }

    if ( options.count == 0 || options.count > MAXIMUM_FASTPING_PACKET_COUNT) {
        Log(LOG_INFO, "Setting packet count to maximum value %d\n",
                MAXIMUM_FASTPING_PACKET_COUNT);
        options.count = MAXIMUM_FASTPING_PACKET_COUNT;
    }

    if( options.size < MINIMUM_FASTPING_PACKET_SIZE ) {
        Log(LOG_INFO, "Setting packet size to minimum value %d\n",
                MINIMUM_FASTPING_PACKET_SIZE);
        options.size = MINIMUM_FASTPING_PACKET_SIZE;
    }

    /* TODO can we just configure one socket in the right address family? */
    if ( configure_socket(&sockets, &options, device, sourcev4, sourcev6) < 0 ){
        exit(EXIT_FAILURE);
    }

    return send_icmp_stream(dests[0], &sockets, &options);
}



/*
 * Print out the RTT and jitter percentile tables.
 */
static void print_percentiles(int32_t *rtt, int32_t *jitter) {
    int i;

    printf("    RTT percentiles        jitter percentiles\n");
    for ( i = 0; i < PERCENTILE_COUNT; i++ ) {
        printf("    %5.01f: %.03f ms", PERCENTILES[i], rtt[i] / 1000.0);
        printf("          %5.01f: %+.03f ms", PERCENTILES[i], jitter[i]/1000.0);
        printf("\n");
    }
}



/*
 * Print out speed in a factor of bits per second.
 */
static void print_datarate(double pps, uint16_t size) {
    double rate = pps * size * 8;
    char *units[] = {"bits", "Kbits", "Mbits", "Gbits", NULL};
    char **unit;

    for ( unit = units; *unit != NULL; unit++ ) {
        if ( rate < 1000 ) {
            printf("(%.02f %s/sec)\n", rate, *unit);
            return;
        }
        rate = rate / 1000;
    }
    printf("(%.02f Tb/sec)\n", rate);
}



/*
 * Unpack the protocol buffer object and print the results of the fastping
 * test.
 */
void print_fastping(amp_test_result_t *result) {
    Amplet2__Fastping__Report *msg;
    Amplet2__Fastping__Item *item;
    Amplet2__Fastping__Header *header;

    char addrstr[INET6_ADDRSTRLEN];
    uint64_t samples;
    double percent;
    double pps;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__fastping__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->reports);

    /* extract the main structs from the message */
    item = msg->reports[0];
    header = msg->header;

    samples = item->rtt ? item->rtt->samples : 0;
    percent = ((double) samples / (double) header->count) * 100;
    inet_ntop(header->family, header->address.data, addrstr, INET6_ADDRSTRLEN);

    /* print basic stats */
    printf("\n");
    printf("AMP fastping test to %s (%s)\n", header->name, addrstr);
    printf("packet count:%" PRIu64 " size:%" PRIu32 " bytes rate:%" PRIu64
            "pps preprobe:%d DSCP:%s(0x%x)\n",
            header->count, header->size, header->rate, header->preprobe,
            dscp_to_str(header->dscp), header->dscp);

    printf("  %" PRIu64 " packets transmitted, %" PRIu64
            " received, %.02f%% packet loss\n",
            header->count, samples, 100 - percent);

    if ( item->rtt ) {
        printf("  %" PRIu64 " rtt samples min/mean/max/sdev = "
                "%.03f/%.03f/%.03f/%.03f ms\n",
                item->rtt->samples, item->rtt->minimum / 1000.0,
                item->rtt->mean / 1000.0, item->rtt->maximum / 1000.0,
                item->rtt->sd / 1000.0);
    }

    if ( item->jitter ) {
        printf("  %" PRIu64 " jitter samples min/mean/max/sdev = "
                "%.03f/%.03f/%.03f/%.03f ms\n",
                item->jitter->samples, item->jitter->minimum / 1000.0,
                item->jitter->mean / 1000.0, item->jitter->maximum / 1000.0,
                item->jitter->sd / 1000.0);
    }

    pps = header->count / (item->runtime/1000000.0);
    printf("  Test ran for %.03lf seconds at %.03f packets per second ",
            item->runtime/1000000.0, pps);

    print_datarate(pps, header->size);

    if ( item->rtt && item->rtt->percentiles &&
            item->jitter && item->jitter->percentiles ) {
        print_percentiles(item->rtt->percentiles, item->jitter->percentiles);
    }

    amplet2__fastping__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_FASTPING;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("fastping");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 300;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_fastping;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_fastping;

    /* the fastping test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the fastping test a SIGINT warning */
    new_test->sigint = 0;

    return new_test;
}
