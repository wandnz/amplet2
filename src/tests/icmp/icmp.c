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
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <libwandevent.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "icmp.h"
#include "icmp.pb-c.h"
#include "debug.h"
#include "icmpcode.h"
#include "dscp.h"
#include "usage.h"
#include "checksum.h"


/*
 * TODO collect more information than what the original icmp test did.
 * Things like rtt could be interesting to track.
 */

static struct option long_options[] = {
    {"perturbate", required_argument, 0, 'p'},
    {"random", no_argument, 0, 'r'},
    {"size", required_argument, 0, 's'},
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



/*
 * Halt the event loop in the event of a SIGINT (either sent from the terminal
 * if running standalone, or sent by the watchdog if running as part of
 * measured) and report the results that have been collected so far.
 */
static void interrupt_test(wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data) {

    Log(LOG_INFO, "Received SIGINT, halting ICMP test");
    ev_hdl->running = false;
}



/*
 * Force the event loop to halt, so we can end the test and report the
 * results that we do have.
 */
static void halt_test(wand_event_handler_t *ev_hdl, void *data) {
    struct icmpglobals_t *globals = (struct icmpglobals_t *)data;

    Log(LOG_DEBUG, "Halting ICMP test due to timeout");
    globals->losstimer = NULL;
    ev_hdl->running = false;
}



/*
 * Check an icmp error to determine if it is in response to a packet we have
 * sent. If it is then the error needs to be recorded.
 */
static int icmp_error(char *packet, int bytes, uint16_t ident,
        struct info_t info[]) {
    struct iphdr *ip, *embed_ip;
    struct icmphdr *icmp, *embed_icmp;
    uint16_t seq;
    int required_bytes;

    ip = (struct iphdr *)packet;

    assert(ip->version == 4);
    assert(ip->ihl >= 5);

    icmp = (struct icmphdr *)(packet + (ip->ihl << 2));

    /*
     * make sure there is enough room in this packet to entertain the
     * possibility of having embedded data - at least enough space for
     * 2 ip headers (one of known length), 2 icmp headers.
     */
    required_bytes = (ip->ihl << 2) + sizeof(struct iphdr) +
        (sizeof(struct icmphdr) * 2);

    if ( bytes < required_bytes || ip->tot_len < required_bytes ) {
	Log(LOG_DEBUG, "ICMP reply too small for embedded packet data "
                "(got %d, need %d", bytes, required_bytes);
	return -1;
    }

    /* get the embedded ip header */
    embed_ip = (struct iphdr *)(packet + ((ip->ihl << 2) +
		sizeof(struct icmphdr)));

    /* obviously not a response to our test, return */
    if ( embed_ip->version != 4 || embed_ip->protocol != IPPROTO_ICMP ) {
        Log(LOG_DEBUG, "Embedded packet isn't ICMPv4\n");
	return -1;
    }

    /* get the embedded icmp header */
    embed_icmp = (struct icmphdr*)(((char *)embed_ip) + (embed_ip->ihl << 2));

    /* make sure the embedded header looks like one of ours */
    if ( embed_icmp->type > NR_ICMP_TYPES ||
	    embed_icmp->type != ICMP_ECHO || embed_icmp->code != 0 ||
	    ntohs(embed_icmp->un.echo.id) != ident) {
        Log(LOG_DEBUG, "Embedded packet ICMP ECHO, or not our ECHO\n");
	return -1;
    }

    seq = ntohs(embed_icmp->un.echo.sequence);
    /*
     * TODO it's possible for this to be clobbered by the most recent error
     * (though unlikely except in the case of redirects). Do we care?
     */
    info[seq].err_type = icmp->type;
    info[seq].err_code = icmp->code;

    /*
     * Don't count a redirect as a response, we are still expecting a real
     * reply from the destination host.
     */
    if ( icmp->type != ICMP_REDIRECT ) {
        info[seq].reply = 1;
    }
    /* TODO get ttl */
    /*info[seq].ttl = */

    return 0;
}



/*
 * Process an ICMPv4 packet to check if it is an ICMP ECHO REPLY in response to
 * a request we have sent. If so then record the time it took to get the reply.
 */
static int process_ipv4_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now) {

    struct iphdr *ip;
    struct icmphdr *icmp;
    uint16_t seq;
    int64_t delay;

    /* make sure that we read enough data to have a valid response */
    if ( bytes < sizeof(struct iphdr) + sizeof(struct icmphdr) +
            sizeof(uint16_t) ) {
        Log(LOG_DEBUG, "Too few bytes read for any valid ICMP response");
        return -1;
    }

    /* any icmpv4 packets we get have full headers attached */
    ip = (struct iphdr *)packet;

    assert(ip->version == 4);
    assert(ip->ihl >= 5);

    /* now make sure that we read enough data for this particular ip header */
    if ( bytes < (ip->ihl << 2) + sizeof(struct icmphdr) + sizeof(uint16_t) ) {
        Log(LOG_DEBUG, "Too few bytes read to contain ICMP header");
        return -1;
    }

    icmp = (struct icmphdr *)(packet + (ip->ihl << 2));

    /* if it isn't an echo reply it could still be an error for us */
    if ( icmp->type != ICMP_ECHOREPLY ) {
	return icmp_error(packet, bytes, globals->ident, globals->info);
    }

    /* if it is an echo reply but the id doesn't match then it's not ours */
    if ( ntohs(icmp->un.echo.id ) != globals->ident ) {
        Log(LOG_DEBUG, "Bad ident (got %d, expected %d)",
                ntohs(icmp->un.echo.id), globals->ident);
	return -1;
    }

    /* check the sequence number is less than the maximum number of requests */
    seq = ntohs(icmp->un.echo.sequence);
    if ( seq > globals->count ) {
        Log(LOG_DEBUG, "Bad sequence number\n");
	return -1;
    }

    /* check that the magic value in the reply matches what we expected */
    if ( *(uint16_t*)(((char *)packet)+(ip->ihl<< 2)+sizeof(struct icmphdr)) !=
	    globals->info[seq].magic ) {
        Log(LOG_DEBUG, "Bad magic value");
	return -1;
    }

    /* reply is good, record the round trip time */
    globals->info[seq].reply = 1;
    globals->outstanding--;

    delay = DIFF_TV_US(*now, globals->info[seq].time_sent);
    if ( delay > 0 ) {
        globals->info[seq].delay = (uint32_t)delay;
    } else {
        globals->info[seq].delay = 0;
    }

    Log(LOG_DEBUG, "Good ICMP ECHOREPLY");
    return 0;
}



/*
 * XXX this won't record errors for ipv6 packets but the ipv4 test will. This
 * is the same behaviour as the original icmp test, but is it really what we
 * want? Should record errors for both protocols, or neither?
 */
static int process_ipv6_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now) {

    struct icmp6_hdr *icmp;
    uint16_t seq;
    int64_t delay;

    if ( bytes < sizeof(struct icmp6_hdr) ) {
        return -1;
    }

    /* any icmpv6 packets we get have the outer ipv6 header stripped */
    icmp = (struct icmp6_hdr *)packet;
    seq = ntohs(icmp->icmp6_seq);

    /* sanity check the various fields of the icmp header */
    if ( icmp->icmp6_type != ICMP6_ECHO_REPLY ||
	    ntohs(icmp->icmp6_id) != globals->ident ||
	    seq > globals->count ) {
	return -1;
    }

    /* check that the magic value in the reply matches what we expected */
    if ( *(uint16_t*)(((char*)packet) + sizeof(struct icmp6_hdr)) !=
	    globals->info[seq].magic ) {
	return -1;
    }

    /* reply is good, record the round trip time */
    globals->info[seq].reply = 1;
    globals->outstanding--;

    delay = DIFF_TV_US(*now, globals->info[seq].time_sent);
    if ( delay > 0 ) {
        globals->info[seq].delay = (uint32_t)delay;
    } else {
        globals->info[seq].delay = 0;
    }

    Log(LOG_DEBUG, "Good ICMP6 ECHOREPLY");
    return 0;
}



/*
 * Callback used when a packet is received that might be a response to one
 * of our probes.
 */
static void receive_probe_callback(wand_event_handler_t *ev_hdl,
        int fd, void *data, enum wand_eventtype_t ev) {

    char packet[RESPONSE_BUFFER_LEN];
    struct timeval now;
    struct iphdr *ip;
    ssize_t bytes;
    int wait;
    struct socket_t sockets;
    struct icmpglobals_t *globals = (struct icmpglobals_t*)data;

    assert(fd > 0);
    assert(ev == EV_READ);

    wait = 0;

    /* the socket used here doesn't matter as the family isn't used anywhere */
    sockets.socket = fd;
    sockets.socket6 = -1;

    if ( (bytes=get_packet(&sockets, packet, RESPONSE_BUFFER_LEN, NULL, &wait,
                    &now)) > 0 ) {
	/*
	 * this check isn't as nice as it could be - should we explicitly ask
	 * for the icmp6 header to be returned so we can be sure we are
	 * checking the right things?
	 */
        ip = (struct iphdr*)packet;
        switch ( ip->version ) {
	    case 4: process_ipv4_packet(globals, packet, bytes, &now);
		    break;
	    default: /* unless we ask we don't have an ipv6 header here */
		    process_ipv6_packet(globals, packet, bytes, &now);
		    break;
	};
    }

    if ( globals->outstanding == 0 && globals->index == globals->count ) {
        /* not waiting on any more packets, exit the event loop */
        ev_hdl->running = false;
        Log(LOG_DEBUG, "All expected ICMP responses received");
    }
}



/*
 * Build the ICMP packet and data that we send as a probe.
 */
static int build_probe(uint8_t family, void *packet, uint16_t packet_size,
        int seq, uint16_t ident, uint16_t magic) {

    struct icmphdr *icmp;
    int hlen;

    assert(packet);
    assert(packet_size >= MIN_PACKET_LEN);

    memset(packet, 0, packet_size);

    icmp = (struct icmphdr*)packet;
    icmp->type = (family == AF_INET) ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(ident);
    icmp->un.echo.sequence = htons(seq);
    memcpy((uint8_t *)packet + sizeof(struct icmphdr), &magic, sizeof(magic));

    if ( family == AF_INET ) {
        hlen = sizeof(struct iphdr);
        icmp->checksum = checksum((uint16_t*)packet, packet_size - hlen);
    } else {
        hlen = sizeof(struct ip6_hdr);
        /* icmp6 checksum will be calculated for us */
    }


    return packet_size - hlen;
}



/*
 * Construct and send an icmp echo request packet.
 */
static void send_packet(wand_event_handler_t *ev_hdl, void *data) {

    char *packet;
    int sock;
    int length;
    int delay;
    int seq;
    uint16_t ident;
    struct addrinfo *dest;
    struct opt_t *opt;
    struct icmpglobals_t *globals;
    struct info_t *info;

    globals = (struct icmpglobals_t *)data;
    info = globals->info;
    seq = globals->index;
    ident = globals->ident;
    dest = globals->dests[seq];
    opt = &globals->options;
    packet = NULL;

    /* save information about this packet so we can track the response */
    memset(&info[seq], 0, sizeof(info[seq]));
    info[seq].addr = dest;
    info[seq].magic = rand();

    /* determine which socket we should use, ipv4 or ipv6 */
    switch ( dest->ai_family ) {
	case AF_INET: sock = globals->sockets.socket; break;
	case AF_INET6: sock = globals->sockets.socket6; break;
	default: Log(LOG_WARNING, "Unknown address family: %d",dest->ai_family);
                 goto next;
    };

    if ( sock < 0 ) {
	Log(LOG_WARNING, "Unable to test to %s, socket wasn't opened",
                dest->ai_canonname);
        goto next;
    }

    /* build the probe packet */
    packet = calloc(1, opt->packet_size);
    length = build_probe(dest->ai_family, packet, opt->packet_size, seq, ident,
            info[seq].magic);

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, packet, length, dest,
                    opt->inter_packet_delay, &(info[seq].time_sent))) > 0 ) {
        usleep(delay);
    }

    if ( delay < 0 ) {
        /* mark this as done if the packet failed to send properly */
        info[seq].reply = 1;
        memset(&(info[seq].time_sent), 0, sizeof(struct timeval));
    } else {
        globals->outstanding++;
    }

next:
    globals->index++;

    /* create timer for sending the next packet if there are still more to go */
    if ( globals->index == globals->count ) {
        Log(LOG_DEBUG, "Reached final target: %d", globals->index);
        globals->nextpackettimer = NULL;
        if ( globals->outstanding == 0 ) {
            /* avoid waiting for LOSS_TIMEOUT if no packets are outstanding */
            ev_hdl->running = false;
        } else {
            globals->losstimer = wand_add_timer(ev_hdl, LOSS_TIMEOUT, 0,
                    globals, halt_test);
        }
    } else {
        globals->nextpackettimer = wand_add_timer(ev_hdl,
                (int) (globals->options.inter_packet_delay / 1000000),
                (globals->options.inter_packet_delay % 1000000),
                globals, send_packet);
    }

    if ( packet ) {
        free(packet);
    }
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

    /* make sure at least one type of socket was opened */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
	return 0;
    }

    return 1;
}



/*
 * Construct a protocol buffer message containing the results for a single
 * destination address.
 */
static Amplet2__Icmp__Item* report_destination(struct info_t *info) {

    Amplet2__Icmp__Item *item =
        (Amplet2__Icmp__Item*)malloc(sizeof(Amplet2__Icmp__Item));

    /* fill the report item with results of a test */
    amplet2__icmp__item__init(item);
    item->has_family = 1;
    item->family = info->addr->ai_family;
    item->name = address_to_name(info->addr);
    item->has_address = copy_address_to_protobuf(&item->address, info->addr);

    if ( info->reply && info->time_sent.tv_sec > 0 &&
            (info->err_type == ICMP_REDIRECT ||
             (info->err_type == 0 && info->err_code == 0)) ) {
        /* report the rtt if we got a valid reply */
        item->has_rtt = 1;
        item->rtt = info->delay;
        item->has_ttl = 1;
        item->ttl = info->ttl;
    } else {
        /* don't send an rtt if there wasn't a valid one recorded */
        item->has_rtt = 0;
        item->has_ttl = 0;
    }

    if ( item->has_rtt || info->err_type > 0 ) {
        /* valid response (0/0) or a useful error, set the type/code fields */
        item->has_err_type = 1;
        item->err_type = info->err_type;
        item->has_err_code = 1;
        item->err_code = info->err_code;
    } else {
        /* missing response, don't include type and code fields */
        item->has_err_type = 0;
        item->has_err_code = 0;
    }

    Log(LOG_DEBUG, "icmp result: %dus, %d/%d\n",
            item->has_rtt?(int)item->rtt:-1, item->err_type, item->err_code);

    return item;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for each destination address.
 */
static amp_test_result_t* report_results(struct timeval *start_time, int count,
        struct info_t info[], struct opt_t *opt) {

    int i;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Log(LOG_DEBUG, "Building icmp report, count:%d psize:%d rand:%d dscp:%0x\n",
            count, opt->packet_size, opt->random, opt->dscp);

    Amplet2__Icmp__Report msg = AMPLET2__ICMP__REPORT__INIT;
    Amplet2__Icmp__Header header = AMPLET2__ICMP__HEADER__INIT;
    Amplet2__Icmp__Item **reports;

    /* populate the header with all the test options */
    header.has_packet_size = 1;
    header.packet_size = opt->packet_size;
    header.has_random = 1;
    header.random = opt->random;
    header.has_dscp = 1;
    header.dscp = opt->dscp;

    /* build up the repeated reports section with each of the results */
    reports = malloc(sizeof(Amplet2__Icmp__Item*) * count);
    for ( i = 0; i < count; i++ ) {
        reports[i] = report_destination(&info[i]);
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = count;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__icmp__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__icmp__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < count; i++ ) {
        free(reports[i]);
    }
    free(reports);

    return result;
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-icmp [-hrvx] [-p perturbate] [-s packetsize]\n"
            "                [-Q codepoint] [-Z interpacketgap]\n"
            "                [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
            "                -- destination1 [destination2 ... destinationN]"
            "\n\n");

    /* test specific options */
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --perturbate     <msec>    "
            "Maximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -r, --random                   "
            "Use a random packet size for each test\n");
    fprintf(stderr, "  -s, --size           <bytes>   "
            "Fixed packet size to use for each test\n");

    print_probe_usage();
    print_interface_usage();
    print_generic_usage();
}



/*
 * Main function to run the icmp test, returning a result structure that will
 * later be printed or sent across the network.
 */
amp_test_result_t* run_icmp(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    struct timeval start_time;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    char *address_string;
    struct icmpglobals_t *globals;
    wand_event_handler_t *ev_hdl = NULL;
    amp_test_result_t *result;

    Log(LOG_DEBUG, "Starting ICMP test");

    wand_event_init();
    ev_hdl = wand_create_event_handler();

    globals = (struct icmpglobals_t *)malloc(sizeof(struct icmpglobals_t));

    /* set some sensible defaults */
    globals->options.dscp = DEFAULT_DSCP_VALUE;
    globals->options.inter_packet_delay = MIN_INTER_PACKET_DELAY;
    globals->options.packet_size = DEFAULT_ICMP_ECHO_REQUEST_LEN;
    globals->options.random = 0;
    globals->options.perturbate = 0;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "p:rs:I:Q:Z:4::6::hvx",
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
            case 'Q': if ( parse_dscp_value(optarg,
                                  &globals->options.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': globals->options.inter_packet_delay = atoi(optarg); break;
            case 'p': globals->options.perturbate = atoi(optarg); break;
            case 'r': globals->options.random = 1; break;
            case 's': globals->options.packet_size = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
	};
    }

    if ( count < 1 ) {
        Log(LOG_WARNING, "No resolvable destinations were specified!");
        exit(EXIT_FAILURE);
    }

    /* pick a random packet size within allowable boundaries */
    if ( globals->options.random ) {
	globals->options.packet_size = MIN_PACKET_LEN +
	    (int)((1500 - MIN_PACKET_LEN) * (random()/(RAND_MAX+1.0)));
	Log(LOG_DEBUG, "Setting packetsize to random value: %d\n",
		globals->options.packet_size);
    }

    /* make sure that the packet size is big enough for our data */
    if ( globals->options.packet_size < MIN_PACKET_LEN ) {
	Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
		globals->options.packet_size, MIN_PACKET_LEN);
	globals->options.packet_size = MIN_PACKET_LEN;
    }

    /* delay the start by a random amount if perturbate is set */
    if ( globals->options.perturbate ) {
	int delay;
	delay = globals->options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		globals->options.perturbate, delay);
	usleep(delay);
    }

    if ( !open_sockets(&globals->sockets) ) {
	Log(LOG_ERR, "Unable to open raw ICMP sockets, aborting test");
	exit(EXIT_FAILURE);
    }

    if ( set_default_socket_options(&globals->sockets) < 0 ) {
        Log(LOG_ERR, "Failed to set default socket options, aborting test");
	exit(EXIT_FAILURE);
    }

    if ( set_dscp_socket_options(&globals->sockets,globals->options.dscp) < 0 ){
        Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
	exit(EXIT_FAILURE);
    }

    if ( device && bind_sockets_to_device(&globals->sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw ICMP socket to device, aborting test");
	exit(EXIT_FAILURE);
    }

    if ( (sourcev4 || sourcev6) &&
            bind_sockets_to_address(
                &globals->sockets, sourcev4, sourcev6) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw ICMP socket to address, aborting test");
	exit(EXIT_FAILURE);
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(EXIT_FAILURE);
    }

    /* use part of the current time as an identifier value */
    globals->ident = (uint16_t)start_time.tv_usec;

    /* allocate space to store information about each request sent */
    globals->info = (struct info_t *)malloc(sizeof(struct info_t) * count);

    globals->index = 0;
    globals->outstanding = 0;
    globals->count = count;
    globals->dests = dests;
    globals->losstimer = NULL;

    /* catch a SIGINT and end the test early */
    wand_add_signal(SIGINT, NULL, interrupt_test);

    /* set up callbacks for receiving packets */
    wand_add_fd(ev_hdl, globals->sockets.socket, EV_READ, globals,
            receive_probe_callback);

    wand_add_fd(ev_hdl, globals->sockets.socket6, EV_READ, globals,
            receive_probe_callback);

    /* schedule the first probe packet to be sent immediately */
    wand_add_timer(ev_hdl, 0, 0, globals, send_packet);

    /* run the event loop till told to stop or all tests performed */
    wand_event_run(ev_hdl);

    /* tidy up after ourselves */
    if ( globals->losstimer ) {
        wand_del_timer(ev_hdl, globals->losstimer);
    }

    if ( globals->nextpackettimer ) {
        wand_del_timer(ev_hdl, globals->nextpackettimer);
    }

    wand_destroy_event_handler(ev_hdl);

    if ( globals->sockets.socket > 0 ) {
	close(globals->sockets.socket);
    }

    if ( globals->sockets.socket6 > 0 ) {
	close(globals->sockets.socket6);
    }

    if ( sourcev4 ) {
        freeaddrinfo(sourcev4);
    }

    if ( sourcev6 ) {
        freeaddrinfo(sourcev6);
    }

    /* send report */
    result = report_results(&start_time, count, globals->info,
            &globals->options);

    free(globals->info);
    free(globals);

    return result;
}



/*
 * Print icmp test results to stdout, nicely formatted for the standalone test
 */
void print_icmp(amp_test_result_t *result) {
    Amplet2__Icmp__Report *msg;
    Amplet2__Icmp__Item *item;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__icmp__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print test header information */
    printf("\nAMP icmp test, %zu destinations, %u byte packets ",
            msg->n_reports, msg->header->packet_size);

    if ( msg->header->random ) {
        printf("(random size)");
    } else {
        printf("(fixed size)");
    }

    printf(", DSCP %s (0x%0x)\n", dscp_to_str(msg->header->dscp),
            msg->header->dscp);

    /* print each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];

        printf("%s", item->name);
        inet_ntop(item->family, item->address.data, addrstr, INET6_ADDRSTRLEN);
        printf(" (%s)", addrstr);

        if ( item->has_rtt ) {
            printf(" %dus", item->rtt);
        } else {
            if ( item->err_type == 0 ) {
                printf(" missing");
            } else {
                printf(" %s (icmp %u/%u)",
                        icmp_code_str(item->family,
                            item->err_type, item->err_code),
                        item->err_type, item->err_code);
            }
        }
        printf("\n");
    }
    printf("\n");

    amplet2__icmp__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_ICMP;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("icmp");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_icmp;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_icmp;

    /* the icmp test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the icmp test a SIGINT warning, it should not take long! */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
int amp_test_process_ipv4_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now) {
    return process_ipv4_packet(globals, packet, bytes, now);
}

amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt) {
    return report_results(start_time, count, info, opt);
}
#endif
