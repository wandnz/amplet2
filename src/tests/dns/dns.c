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
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <libwandevent.h>

#include "config.h"
#include "tests.h"
#include "debug.h"
#include "testlib.h"
#include "dns.h"
#include "dns.pb-c.h"
#include "dscp.h"
#include "usage.h"


static struct option long_options[] = {
    {"class", required_argument, 0, 'c'},
    {"nsid", no_argument, 0, 'n'},
    {"perturbate", required_argument, 0, 'p'},
    {"query", required_argument, 0, 'q'},
    {"recurse", no_argument, 0, 'r'},
    {"dnssec", no_argument, 0, 's'},
    {"type", required_argument, 0, 't'},
    {"payload", required_argument, 0, 'z'},
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
    struct dnsglobals_t *globals = (struct dnsglobals_t *)data;

    Log(LOG_DEBUG, "Halting DNS test due to timeout");
    globals->losstimer = NULL;
    ev_hdl->running = false;
}



/*
 * Decode a compressed name/label. Each portion of the name is preceeded by a
 * byte containing its length. The final portion of any name can be
 * represented in two bytes (magic number + offset) describing a previously
 * used label rather than having to write it out in full.
 * See section 4.1.4 of http://www.ietf.org/rfc/rfc1035.txt
 */
static char *decode(char *result, char *data, char *start) {
    int index = 0;
    uint8_t length;
    char *current = NULL;

    assert(data);
    assert(start);

    do {
	/* rdata length is the first byte */
	length = (uint8_t)*start;

	/*
	 * If the length shows that it's compressed (magic number 0xc0) then
	 * update the pointer and try again. The next byte contains the index
	 * into data that we should jump to. Multiple levels of indirection are
	 * possible, so we can't just carry on here, have to keep checking.
	 */
	if ( (length & 0xc0) == 0xc0 ) {
	    /* if going back into the packet, save where we are up to */
	    if ( current == NULL ) {
		current = start + 2; /* skip the 2 bytes of compression data */
	    }
	    /* offset is 14 bits wide, ignore the first 2 that are set */
	    start = data + ( ((*start) & 0x3f) << 8 | ((*(start+1)) & 0xff) );
	    continue;
	}

	/* found a normally encoded length-value pair, add to the full name */
	if ( length > 0 ) {
	    /* save the name if space has been allocated for it */
	    if ( result != NULL ) {
		/* name parts should have dots between them */
		if ( index > 0 ) {
		    result[index] = '.';
		    index++;
		}
		/* append the newest name part */
		strncpy(result+index, (char*)(start+1), length);
	    }
	    index += length;
	    start += length + 1;
	}
    } while ( length > 0 ); /* zero length element signifies the end */

    /* null terminate result string */
    if ( result != NULL ) {
	result[index] = '\0';
    }

    /*
     * if we've saved the current location while looking back in the packet,
     * return the saved location. This will be 2 bytes ahead of where we
     * started, i.e. 0xc0 and the offset byte.
     */
    if ( current != NULL ) {
	return current;
    }

    /*
     * if the name was written in full and not compressed then start has been
     * updated as we went. Increment one to get past the last byte of the name
     * and return that as the start of the next record.
     */
    return start + 1;
}



/*
 * Encode a compressed name/label. Each portion of the name is preceeded by
 * a length byte. Dots are not represented in the query.
 * See section 4.1.4 of http://www.ietf.org/rfc/rfc1035.txt
 */
static char *encode(char *query) {
    char *name = malloc(MAX_DNS_NAME_LEN * sizeof(char));
    char *query_index = query;
    char *dot;
    int name_index = 0;
    int length;

    do {
	/* each part of the query is separated by dots */
	dot = index(query_index, '.');
	if ( dot == NULL )
	    length = strlen(query_index);
	else
	    length = dot - query_index;

	/* copy length */
	name[name_index] = length;
	/* copy the string of that length */
	memcpy(name+name_index+1, query_index, length);
	name_index += length+1;
	query_index += length+1;

    } while ( dot != NULL );

    /* zero length finishes the query */
    name[name_index] = 0;

    return name;
}



/*
 * Decode an OPT resource record. Currently the only one that we look for
 * is the NSID OPT RR.
 */
static void process_opt_rr(void *rr, uint16_t rrlen, struct info_t *info) {
    char *option = rr;
    struct dns_opt_rdata_t *rdata;

    /* check every option record for ones that we understand */
    do {
        rdata = (struct dns_opt_rdata_t*)option;
        switch ( ntohs(rdata->code) ) {
            case 3: /* NSID */
                info->nsid_length = ntohs(rdata->length);
                info->nsid_payload = malloc(info->nsid_length);
                Log(LOG_DEBUG, "Got NSID response of length %d",
                        info->nsid_length);
                memcpy(info->nsid_payload,
                        option + sizeof(struct dns_opt_rdata_t),
                        info->nsid_length);
                break;
            default: break;
        };

        option += ntohs(rdata->length) + sizeof(struct dns_opt_rdata_t);
        rrlen -= sizeof(struct dns_opt_rdata_t);
        rrlen -= ntohs(rdata->length);

    } while ( rrlen > 0 );
    assert(rrlen == 0);
}



/*
 * Process a received DNS packet to make sure it is a proper response to our
 * query, and if so, record details on the response.
 *
 * TODO what if the packet isn't long enough for the amount of data that it
 * claims to have?
 */
static void process_packet(struct dnsglobals_t *globals, char *packet,
        __attribute__((unused))uint32_t bytes, struct timeval *now) {

    struct dns_t *header;
    uint16_t recv_ident;
    int index;
    char *rr_start = NULL;
    struct dns_opt_rr_t *rr_data;
    char *name;
    int i;
    int response_count;
    struct info_t *info;
    int64_t delay;

    info = globals->info;

    header = (struct dns_t *)packet;
    recv_ident = ntohs(header->id);

    /* make sure the id field in this packet matches our request */
    if ( recv_ident < globals->ident ||
            (recv_ident - globals->ident) > globals->count ) {
	Log(LOG_DEBUG, "Incoming DNS packet with invalid ID number");
	return;
    }

    index = recv_ident - globals->ident;
    info[index].reply = 1;
    info[index].flags.bytes = header->flags.bytes;
    info[index].total_answer = ntohs(header->an_count);
    info[index].total_authority = ntohs(header->ns_count);
    info[index].total_additional = ntohs(header->ar_count);
    info[index].response_code = RESPONSEOK;
    /* info[index].ttl = */

    response_count = ntohs(header->an_count + header->ns_count +
	    header->ar_count);

    /* check it for errors */
    if ( ! header->flags.fields.qr ) {
	/* is this packet actually a response to a query? */
	info[index].response_code = INVALID;
    } else if ( ntohs(header->qd_count) != 1 ) {
	/* we only sent one request, make sure that matches */
	info[index].response_code = INVALID;
    } else if ( header->flags.fields.rcode ) {
	/* are there any errors in the response code (non-zero value)? */
	info[index].response_code = NOTFOUND;
    } else if ( response_count < 1 ) {
	/* make sure there was at least something resembling an answer */
	info[index].response_code = NOTFOUND;
    }

    /* if it's a response to our query then check its contents */
    if ( info[index].response_code == RESPONSEOK ||
            info[index].response_code == NOTFOUND ) {

	rr_start = packet + sizeof(struct dns_t);

	/* skip over all the question RRs, we aren't really interested */
	for ( i=0; i<ntohs(header->qd_count); i++ ) {
	    Log(LOG_DEBUG, "Skipping question RR %d/%d\n", i+1,
		    ntohs(header->qd_count));
	    rr_start = decode(NULL, packet, rr_start);
	    rr_start += sizeof(struct dns_query_t);
	}

	for ( i=0; i<response_count; i++ ) {

	    name = malloc(MAX_DNS_NAME_LEN * sizeof(char));

	    /* decode will update rr_start to the next byte after the name */
	    rr_start = decode(name, packet, rr_start);
	    rr_data = (struct dns_opt_rr_t *)rr_start;

	    Log(LOG_DEBUG, "RR: '%s' type=0x%.2x class=0x%.2x rdlen=%d\n",
		    name, htons(rr_data->type), htons(rr_data->payload),
		    htons(rr_data->rdlen));

	    /* deal with any record types that we are interested in */
	    switch ( ntohs(rr_data->type) ) {
		case 1: /* A record, nothing to do? */
		    break;

		case 28: /* AAAA record, nothing to do? */
		    break;

		case 41: /* OPT RR */
		    /* ensure there is enough data for a RR to be present */
		    if ( ntohs(rr_data->rdlen) >=
			    sizeof(struct dns_opt_rdata_t) ) {
			/* skip fixed part of RR header to variable rdata */
			process_opt_rr((void*)(rr_data + 1),
                                ntohs(rr_data->rdlen), &info[index]);
		    }
		    break;

		case 46: /* RRSIG */
		    info[index].rrsig = 1;
		    break;

		default:
		    break;
	    };

	    /* carry on to the next RR */
	    rr_start += sizeof(struct dns_opt_rr_t);
	    rr_start += ntohs(rr_data->rdlen);
	    free(name);
	}
    }

    /*
     * This catches the case where the response is invalid. Is this the sort
     * of behaviour we want here, or should we still investigate the packet?
     */
    if ( rr_start == NULL ) {
        info[index].bytes = 0;
    } else {
        info[index].bytes = rr_start - packet;
    }

    delay = DIFF_TV_US(*now, info[index].time_sent);
    if ( delay > 0 ) {
        info[index].delay = (uint32_t)delay;
    } else {
        info[index].delay = 0;
    }
    globals->outstanding--;
}



/*
 * Callback used when a packet is received that might be a response to one
 * of our probes.
 */
static void receive_probe_callback(wand_event_handler_t *ev_hdl,
        int fd, void *data, enum wand_eventtype_t ev) {

    char *packet;
    int buflen;
    ssize_t bytes;
    int wait;
    struct timeval now;
    struct socket_t sockets;
    struct dnsglobals_t *globals = (struct dnsglobals_t*)data;

    assert(fd > 0);
    assert(ev == EV_READ);

    if ( globals->options.udp_payload_size > 0 ) {
        buflen = globals->options.udp_payload_size;
    } else {
        buflen = DEFAULT_UDP_PAYLOAD_SIZE;
    }

    wait = 0;
    sockets.socket = fd;
    sockets.socket6 = -1;

    packet = calloc(1, buflen);

    if ( (bytes=get_packet(&sockets, packet, buflen, NULL, &wait, &now)) > 0 ) {
        process_packet(globals, packet, bytes, &now);
    }

    if ( globals->outstanding == 0 && globals->index == globals->count ) {
        /* not waiting on any more packets, exit the event loop */
        ev_hdl->running = false;
        Log(LOG_DEBUG, "All expected DNS responses received");
    }

    free(packet);
}



/*
 * Build a DNS query based on the user options.
 */
static char *create_dns_query(uint16_t ident, uint32_t *len, struct opt_t *opt){
    uint32_t total_len;
    struct dns_t *header;
    struct dns_query_t *query_info;
    struct dns_opt_rr_t *additional;
    char *query;
    char *query_string;
    int query_string_len;

    /* encode query string */
    query_string = encode(opt->query_string);
    query_string_len = strlen(query_string) + 1;
    total_len = sizeof(struct dns_t) + query_string_len +
	sizeof(struct dns_query_t);

    /*
     * if we are doing dnssec or nsid then there is an OPT pseudo RR header
     * with a 1 byte, zero length name field
     */
    if ( opt->dnssec || opt->nsid || opt->udp_payload_size ) {
	total_len += SIZEOF_PSEUDO_RR;

	if ( opt->nsid ) {
	    total_len += sizeof(struct dns_opt_rdata_t);
	}
    }

    /* create the packet big enough to fit all our bits */
    query = malloc(total_len);
    memset(query, 0, total_len);

    /* map a dns header over the first portion of the query buffer */
    header = (struct dns_t*)query;

    /* set the recursion desired flag appropriately */
    if ( opt->recurse ) {
	header->flags.fields.rd = 1;
    }

    /* query id */
    header->id = ntohs(ident);

    /* there is only a single query in this packet */
    header->qd_count = htons(1);

    /* if doing dnssec or nsid then there is also an additional section */
    if ( opt->dnssec || opt->nsid || opt->udp_payload_size ) {
	header->ar_count = htons(1);
    }

    /* the encoded query goes after the dns header */
    memcpy(query + sizeof(struct dns_t), query_string, query_string_len);
    free(query_string);

    /* set the type and class after the query */
    query_info = (struct dns_query_t*)(query + sizeof(struct dns_t) +
	query_string_len);
    query_info->type = htons(opt->query_type);
    query_info->class = htons(opt->query_class);

    /* add the additional RR to end of the packet if doing dnssec or nsid */
    if ( opt->dnssec || opt->nsid || opt->udp_payload_size ) {
	additional = (struct dns_opt_rr_t*)(query + query_string_len +
		sizeof(struct dns_t) + sizeof(struct dns_query_t) +
		sizeof(uint8_t));
	additional->type = htons(41); /* OPT header */
	additional->payload = htons(opt->udp_payload_size);

	if ( opt->dnssec ) {
	    /* set the DNSSEC OK bit */
	    additional->z = htons(0x8000);
	}

	if ( opt->nsid ) {
	    struct dns_opt_rdata_t *nsid_info;
	    nsid_info = (struct dns_opt_rdata_t*)(additional + 1);
	    nsid_info->code = htons(3);
	    nsid_info->length = 0;
	    additional->rdlen = htons(sizeof(struct dns_opt_rdata_t));
	}
    }

    *len = total_len;
    return query;
}



/*
 * Send a DNS packet and record information about when it was sent.
 */
static void send_packet(wand_event_handler_t *ev_hdl, void *data) {

    int sock;
    int delay;
    char *qbuf;
    int seq;
    uint16_t ident;
    struct addrinfo *dest;
    struct opt_t *opt;
    struct dnsglobals_t *globals;
    struct info_t *info;

    globals = (struct dnsglobals_t *)data;
    info = globals->info;
    seq = globals->index;
    ident = globals->ident;
    dest = globals->dests[seq];
    opt = &globals->options;
    qbuf = NULL;

    /*
     * Set initial values for the info block for this test - it has already
     * been memset to zero, so only need to set those that have values. Do
     * this before any return statements, so we have a little bit of info
     * in case we abort early.
     */
    info[seq].addr = dest;

    /* determine the appropriate socket to use and port field to set */
    switch ( dest->ai_family ) {
	case AF_INET:
	    sock = globals->sockets.socket;
	    ((struct sockaddr_in*)dest->ai_addr)->sin_port = htons(53);
	    break;
	case AF_INET6:
	    sock = globals->sockets.socket6;
	    ((struct sockaddr_in6*)dest->ai_addr)->sin6_port = htons(53);
	    break;
	default:
	    Log(LOG_WARNING, "Unknown address family: %d", dest->ai_family);
	    goto next;
    };

    if ( sock < 0 ) {
	Log(LOG_WARNING, "Unable to test to %s, socket wasn't opened",
                dest->ai_canonname);
	goto next;
    }

    //XXX pass in buffer, return useful length like icmp test?
    qbuf = create_dns_query(seq + ident, &(info[seq].query_length), opt);

    while ( (delay = delay_send_packet(sock, qbuf, info[seq].query_length,
                    dest, opt->inter_packet_delay,
                    &(info[seq].time_sent))) > 0 ) {
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

    if ( qbuf ) {
        free(qbuf);
    }
}



/*
 * Open the UDP sockets used for this test.
 */
static int open_sockets(struct socket_t *sockets) {
    if ( (sockets->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
	Log(LOG_WARNING, "Failed to open socket for IPv4");
    }

    if ( (sockets->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
	Log(LOG_WARNING, "Failed to open socket for IPv6");
    }

    /* make sure at least one type of socket was opened */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
	return 0;
    }

    return 1;
}



/*
 * Construct a protocol buffer message containing the DNS header flags for one
 * query response.
 */
static Amplet2__Dns__DnsFlags* report_flags(union flags_t *flags) {

    Amplet2__Dns__DnsFlags *item = (Amplet2__Dns__DnsFlags*)malloc(
            sizeof(Amplet2__Dns__DnsFlags));
    amplet2__dns__dns_flags__init(item);

    item->has_qr = 1;
    item->qr = flags->fields.qr;
    item->has_opcode = 1;
    item->opcode = flags->fields.opcode;
    item->has_aa = 1;
    item->aa = flags->fields.aa;
    item->has_tc = 1;
    item->tc = flags->fields.tc;
    item->has_rd = 1;
    item->rd = flags->fields.rd;
    item->has_ra = 1;
    item->ra = flags->fields.ra;
    item->has_z = 1;
    item->z = flags->fields.z;
    item->has_ad = 1;
    item->ad = flags->fields.ad;
    item->has_cd = 1;
    item->cd = flags->fields.cd;
    item->has_rcode = 1;
    item->rcode = flags->fields.rcode;

    return item;
}



/*
 * Construct a protocol buffer message containing the results for a single
 * destination address.
 */
static Amplet2__Dns__Item* report_destination(struct info_t *info) {

    Amplet2__Dns__Item *item =
        (Amplet2__Dns__Item*)malloc(sizeof(Amplet2__Dns__Item));

    /* fill the report item with results of a test */
    amplet2__dns__item__init(item);
    item->has_family = 1;
    item->family = info->addr->ai_family;
    item->name = address_to_name(info->addr);
    item->has_address = copy_address_to_protobuf(&item->address, info->addr);

    /* only count query length if we actually sent the query */
    if ( info->time_sent.tv_sec > 0 ) {
        item->has_query_length = 1;
        item->query_length = info->query_length;
    }

    /* TODO check response code too? */
    if ( info->reply && info->time_sent.tv_sec > 0 ) {
        item->has_rtt = 1;
        item->rtt = info->delay;
        item->has_ttl = 1;
        item->ttl = info->ttl;
        item->has_response_size = 1;
        item->response_size = info->bytes;
        item->has_total_answer = 1;
        item->total_answer = info->total_answer;
        item->has_total_authority = 1;
        item->total_authority = info->total_authority;
        item->has_total_additional = 1;
        item->total_additional = info->total_additional;
        item->flags = report_flags(&info->flags);
        item->has_rrsig = 1;
        item->rrsig = info->rrsig;

        /* possible instance name from NSID OPT RR */
        if ( info->nsid_length > 0 ) {
            item->has_instance = 1;
            item->instance.len = info->nsid_length;
            item->instance.data = info->nsid_payload;
        } else {
            item->has_instance = 0;
        }
    } else {
        /* don't report any of these fields without a response to our query */
        item->has_rtt = 0;
        item->has_ttl = 0;
        item->has_response_size = 0;
        item->has_total_answer = 0;
        item->has_total_authority = 0;
        item->has_total_additional = 0;
        item->flags = NULL;
        item->has_instance = 0;
        item->has_rrsig = 0;
    }

    Log(LOG_DEBUG, "dns result: %dus\n", item->has_rtt ? (int)item->rtt : -1);

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

    Log(LOG_DEBUG, "Building dns report, count:%d, query:%s\n",
	    count, opt->query_string);

    Amplet2__Dns__Report msg = AMPLET2__DNS__REPORT__INIT;
    Amplet2__Dns__Header header = AMPLET2__DNS__HEADER__INIT;
    Amplet2__Dns__Item **reports;

    /* populate the header with all the test options */
    header.has_query_type = 1;
    header.query_type = opt->query_type;
    header.has_query_class = 1;
    header.query_class = opt->query_class;
    header.has_recurse = 1;
    header.recurse = opt->recurse;
    header.has_dnssec = 1;
    header.dnssec = opt->dnssec;
    header.has_nsid = 1;
    header.nsid = opt->nsid;
    header.has_udp_payload_size = 1;
    header.udp_payload_size = opt->udp_payload_size;
    header.query = opt->query_string;
    header.has_dscp = 1;
    header.dscp = opt->dscp;

    /* build up the repeated reports section with each of the results */
    reports = malloc(sizeof(Amplet2__Dns__Item*) * count);
    for ( i = 0; i < count; i++ ) {
        reports[i] = report_destination(&info[i]);
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = count;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__dns__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__dns__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < count; i++ ) {
        /* TODO can't free here or it breaks the unit test, move elsewhere  */
        //free(info[i].nsid_payload);
        if ( reports[i]->flags ) {
            free(reports[i]->flags);
        }
        free(reports[i]);
    }

    free(reports);

    return result;
}



/*
 * Convert query type string from the command line into the value used in
 * the DNS header.
 */
static uint16_t get_query_type(char *query_type) {
    uint16_t value;

    if(strcasecmp(query_type, "A") == 0)
	return 0x01;
    if(strcasecmp(query_type, "NS") == 0)
	return 0x02;
    if(strcasecmp(query_type, "AAAA") == 0)
	return 0x1c;
    if(strcasecmp(query_type, "PTR") == 0)
	return 0x0c;
    if(strcasecmp(query_type, "MX") == 0)
	return 0x0f;
    if(strcasecmp(query_type, "SOA") == 0)
	return 0x06;
    if(strcasecmp(query_type, "TXT") == 0)
        return 0x10;
    if(strcasecmp(query_type, "ANY") == 0)
	return 0xff;

    if ( (value = atoi(query_type)) > 0 ) {
	return value;
    }

    return 0;
}



/*
 * Convert the query type value used in the DNS header into a string suitable
 * for printing.
 */
static char *get_query_type_string(uint16_t query_type) {
    switch ( query_type ) {
	case 0x01: return "A";
	case 0x02: return "NS";
	case 0x1c: return "AAAA";
	case 0x0c: return "PTR";
	case 0x0f: return "MX";
	case 0x06: return "SOA";
	case 0x10: return "TXT";
	case 0xff: return "ANY";
	default: return "unknown";
    };
}



/*
 * Convert query class string from the command line into the value used in
 * the DNS header.
 */
static uint16_t get_query_class(char *query_class) {
    uint16_t value;

    if ( strcasecmp(query_class, "IN") == 0 )
	return 0x01;

    if ( (value = atoi(query_class)) > 0 ) {
	return value;
    }

    return 0;
}



/*
 * Convert the query class value used in the DNS header into a string suitable
 * for printing.
 */
static char *get_query_class_string(uint16_t query_class) {
    switch ( query_class ) {
	case 0x01: return "IN";
	default: return "unknown";
    };
}



/*
 * Convert the opcode value used in the DNS header into a string suitable
 * for printing.
 */
static char *get_opcode_string(uint8_t opcode) {
    switch ( opcode ) {
	case 0x00: return "QUERY";
	case 0x01: return "IQUERY";
	case 0x02: return "STATUS";
	case 0x04: return "NOTIFY";
	case 0x05: return "UPDATE";
	default: return "unknown";
    };
}



/*
 * Convert the status value used in the DNS header into a string suitable
 * for printing.
 */
static char *get_status_string(uint8_t status) {
    switch ( status ) {
	case 0x00: return "NOERROR";
	case 0x01: return "FORMERR";
	case 0x02: return "SERVFAIL";
	case 0x03: return "NXDOMAIN";
	case 0x04: return "NOTIMP";
	case 0x05: return "REFUSED";
	case 0x06: return "YXDOMAIN";
	case 0x07: return "YXRRSET";
	case 0x08: return "NXRRSET";
	case 0x09: return "NOTAUTH";
	case 0x0a: return "NOTZONE";
	default: return "unknown";
    };
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-dns [-hrnsvx] [-c class] [-p perturbate] [-q query]\n"
            "               [-t type] [-z size]\n"
            "               [-Q codepoint] [-Z interpacketgap]\n"
            "               [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
            "               [-- destination1 [ destination2 ... destinationN]]"
            "\n\n");

    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --class          <class>   "
            "Class type to search for (default: IN)\n");
    fprintf(stderr, "  -n, --nsid                     "
            "Do NSID query (default: false)\n");
    fprintf(stderr, "  -p, --perturbate     <msec>    "
            "Maximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -q, --query          <query>   "
            "Query string (eg the hostname to look up)\n");
    fprintf(stderr, "  -r, --recurse                  "
            "Allow recursive queries (default: false)\n");
    fprintf(stderr, "  -s, --dnssec                   "
            "Use DNSSEC (default: false)\n");
    fprintf(stderr, "  -t, --type           <type>    "
            "Record type to search for (default: A)\n");
    fprintf(stderr, "  -z, --payload        <size>    "
            "UDP payload size (default: %d, 0 to disable)\n",
            DEFAULT_UDP_PAYLOAD_SIZE);

    print_interface_usage();
    print_generic_usage();
}



/*
 * Main function to run the dns test, returning a result structure that will
 * later be printed or sent across the network.
 */
amp_test_result_t* run_dns(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    struct opt_t *options;
    struct timeval start_time;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    char *address_string;
    int local_resolv;
    struct dnsglobals_t *globals;
    wand_event_handler_t *ev_hdl = NULL;
    amp_test_result_t *result;

    Log(LOG_DEBUG, "Starting DNS test");

    wand_event_init();
    ev_hdl = wand_create_event_handler();

    globals = (struct dnsglobals_t *)malloc(sizeof(struct dnsglobals_t));

    /* set some sensible defaults */
    options = &globals->options;
    options->query_string = NULL;
    options->query_type = 0x01;
    options->query_class = 0x01;
    options->udp_payload_size = DEFAULT_UDP_PAYLOAD_SIZE;
    options->recurse = 0;
    options->dnssec = 0;
    options->nsid = 0;
    options->perturbate = 0;
    options->inter_packet_delay = MIN_INTER_PACKET_DELAY;
    options->dscp = DEFAULT_DSCP_VALUE;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;
    local_resolv = 0;

    while ( (opt = getopt_long(argc, argv, "c:np:q:rst:z:I:Q:Z:4::6::hvx",
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
            case 'Q': if ( parse_dscp_value(optarg, &options->dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': options->inter_packet_delay = atoi(optarg); break;
            case 'c': options->query_class = get_query_class(optarg); break;
            case 'n': options->nsid = 1; break;
            case 'p': options->perturbate = atoi(optarg); break;
            case 'q': options->query_string = strdup(optarg); break;
            case 'r': options->recurse = 1; break;
            case 's': options->dnssec = 1; break;
            case 't': options->query_type = get_query_type(optarg); break;
            case 'z': options->udp_payload_size = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( options->query_string == NULL ) {
        usage();
        exit(EXIT_FAILURE);
    }

    assert(strlen(options->query_string) < MAX_DNS_NAME_LEN);
    assert(options->query_type > 0);
    assert(options->query_class > 0);

    /*
     * If we set this to zero (and aren't doing dnssec or nsid) then don't send
     * an EDNS header. Otherwise values lower than 512 MUST be treated as equal
     * to 512 (RFC 6891).
     */
    if ( (options->udp_payload_size != 0 || options->dnssec || options->nsid )
            && options->udp_payload_size < MIN_UDP_PAYLOAD_SIZE ) {
        Log(LOG_WARNING, "UDP payload size %d too low, increasing to %d",
                options->udp_payload_size, MIN_UDP_PAYLOAD_SIZE);
        options->udp_payload_size = MIN_UDP_PAYLOAD_SIZE;
    }

    /* if no destinations have been set then try to use /etc/resolv.conf */
    if ( count == 0 && dests == NULL ) {
        FILE *resolv;
        char line[MAX_RESOLV_CONF_LINE];
        char nameserver[MAX_DNS_NAME_LEN];
        struct addrinfo *addr;

        Log(LOG_DEBUG, "No destinations set, checking /etc/resolve.conf");

        /* There is a define _PATH_RESCONF in resolv.h should we use it? */
        if ( (resolv = fopen("/etc/resolv.conf", "r")) == NULL ) {
            Log(LOG_WARNING, "Failed to open /etc/resolv.conf for reading: %s",
                    strerror(errno));
            return NULL;
        }

        /*
         * Read each line of /etc/resolv.conf and extract just the nameserver
         * lines as our destinations to query.
         */
        while ( fgets(line, MAX_RESOLV_CONF_LINE, resolv) != NULL ) {
            if ( sscanf(line, "nameserver %s\n", (char*)&nameserver) == 1 ) {
                Log(LOG_DEBUG, "Got nameserver: %s", nameserver);

                if ( (addr = get_numeric_address(nameserver, NULL)) == NULL ) {
                    continue;
                }

                /* need a name to report the results under, use the address */
                addr->ai_canonname = strdup(LOCALDNS_REPORT_NAME);

                /* just put the first resolved address in the dest list */
                dests = realloc(dests, (count + 1) * sizeof(struct addrinfo*));
                dests[count] = addr;
                count++;
            }
        }

        /* mark it so we know that we have to free dests ourselves later */
        local_resolv = 1;
        fclose(resolv);
    }

    /* delay the start by a random amount of perturbate is set */
    if ( options->perturbate ) {
	int delay;
	delay = options->perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		options->perturbate, delay);
	usleep(delay);
    }

    if ( !open_sockets(&globals->sockets) ) {
	Log(LOG_ERR, "Unable to open sockets, aborting test");
	free(options->query_string);
        exit(EXIT_FAILURE);
    }

    if ( set_default_socket_options(&globals->sockets) < 0 ) {
        Log(LOG_ERR, "Failed to set default socket options, aborting test");
        exit(EXIT_FAILURE);
    }

    if ( set_dscp_socket_options(&globals->sockets, options->dscp) < 0 ) {
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
	free(options->query_string);
        exit(EXIT_FAILURE);
    }

    /* use part of the current time as an identifier value */
    globals->ident = (uint16_t)start_time.tv_usec;

    /* allocate space to store information about each request sent */
    globals->info = (struct info_t *)malloc(sizeof(struct info_t) * count);
    memset(globals->info, 0, sizeof(struct info_t) * count);

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
    result = report_results(&start_time, count, globals->info, options);

    free(options->query_string);
    free(globals->info);
    free(globals);

    /* free any addresses we've had to make ourselves */
    if ( local_resolv && dests ) {
        while ( count > 0 ) {
            freeaddrinfo(dests[count-1]);
            count--;
        }
        free(dests);
    }

    return result;
}



/*
 * Print DNS test results to stdout, nicely formatted for the standalone test.
 * Tries to look a little bit similar to the output of dig, but with fewer
 * lines of output per server.
 */
void print_dns(amp_test_result_t *result) {
    Amplet2__Dns__Report *msg;
    Amplet2__Dns__Item *item;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__dns__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print global configuration options */
    printf("\n");
    printf("AMP dns test, %zu destinations, %s %s %s,",
	    msg->n_reports, msg->header->query,
	    get_query_class_string(msg->header->query_class),
	    get_query_type_string(msg->header->query_type));
    printf(" DSCP %s (0x%0x)", dscp_to_str(msg->header->dscp),
            msg->header->dscp);
    printf("\n");

    if ( msg->header->recurse || msg->header->dnssec || msg->header->nsid ) {
	printf("global options:");
	if ( msg->header->recurse ) printf(" +recurse");
	if ( msg->header->dnssec ) printf(" +dnssec");
	if ( msg->header->nsid ) printf(" +nsid");
	printf("\n");
    }

    /* print per test results */
    for ( i=0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];

	printf("SERVER: %s", item->name);
	inet_ntop(item->family, item->address.data, addrstr, INET6_ADDRSTRLEN);

        /* nothing further we can do if there is no rtt - no good response */
        if ( !item->has_rtt ) {
            printf(" (%s) no response\n\n", addrstr);
            continue;
        }

        printf(" (%s) %dus\n", addrstr, item->rtt);

        /* if present, print instance name / nsid payload like dig does */
        if ( item->instance.len > 0 ) {
            int j;
            printf("NSID: ");
            /* print nsid as hex string */
            for ( j=0; j < (int)item->instance.len; j++ ) {
                printf("%02x ", item->instance.data[j]);
            }
            /* print the printable characters in nsid */
            printf("(\"");
            for ( j=0; j < (int)item->instance.len; j++ ) {
                if ( isprint(item->instance.data[j]) ) {
                    printf("%c", item->instance.data[j]);
                } else {
                    printf(".");
                }
            }
            printf("\")\n");
        }

        printf("MSG SIZE sent: %d, rcvd: %d, ", item->query_length,
                item->response_size);

        if ( item->flags ) {
            printf("opcode: %s, status: %s\n",
                    get_opcode_string(item->flags->opcode),
                    get_status_string(item->flags->rcode));

            printf("flags:");
            if ( item->flags->qr ) printf(" qr");
            if ( item->flags->aa ) printf(" aa");
            if ( item->flags->rd ) printf(" rd");
            if ( item->flags->ra ) printf(" ra");
            if ( item->flags->tc ) printf(" tc");
            if ( item->flags->ad ) printf(" ad");
            if ( item->flags->cd ) printf(" cd");
            printf("; ");
        }

        printf("QUERY:1, ANSWER:%d, AUTHORITY:%d, ADDITIONAL:%d",
                item->total_answer, item->total_authority,
                item->total_additional);

        if ( msg->header->dnssec ) {
            printf(", RRSIG:");
            if ( item->rrsig ) {
                printf("yes");
            } else {
                printf("no");
            }
        }
        printf("\n\n");
    }

    amplet2__dns__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_DNS;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("dns");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_dns;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_dns;

    /* the dns test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the DNS test a SIGINT warning, it should not take long! */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
char *amp_test_dns_encode(char *query) {
    return encode(query);
}

char *amp_test_dns_decode(char *result, char *data, char *start) {
    return decode(result, data, start);
}

amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt) {
    return report_results(start_time, count, info, opt);
}

#endif
