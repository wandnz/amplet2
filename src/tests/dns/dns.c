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
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>

#include "config.h"
#include "tests.h"
#include "debug.h"
#include "testlib.h"
#include "dns.h"
#include "dns.pb-c.h"


static struct option long_options[] = {
    {"class", required_argument, 0, 'c'},
    {"help", no_argument, 0, 'h'},
    {"interface", required_argument, 0, 'I'},
    {"nsid", no_argument, 0, 'n'},
    {"perturbate", required_argument, 0, 'p'},
    {"query", required_argument, 0, 'q'},
    {"recurse", no_argument, 0, 'r'},
    {"dnssec", no_argument, 0, 's'},
    {"type", required_argument, 0, 't'},
    {"version", no_argument, 0, 'v'},
    {"payload", required_argument, 0, 'z'},
    {"ipv4", required_argument, 0, '4'},
    {"ipv6", required_argument, 0, '6'},
    {NULL, 0, 0, 0}
};



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
static void process_opt_rr(char *rr, struct info_t *info) {
    char *option = rr;
    struct dns_opt_rdata_t *rdata;

    /* check every option record for ones that we understand */
    do {
	rdata = (struct dns_opt_rdata_t*)option;
	switch ( rdata->code ) {
	    case 3: /* NSID */
		/* TODO decode name (if we find out how) */
		strncpy(info->response, "placeholder", 11);
		break;
	    default: break;
	};

	option += rdata->length + sizeof(struct dns_opt_rdata_t);

    } while ( rdata->length > 0 );
}



/*
 * Process a received DNS packet to make sure it is a proper response to our
 * query, and if so, record details on the response.
 *
 * TODO what if the packet isn't long enough for the amount of data that it
 * claims to have?
 */
static void process_packet(char *packet, uint16_t ident, struct timeval *now,
	int count, struct info_t info[]) {

    struct dns_t *header;
    uint16_t recv_ident;
    int index;
    char *rr_start = NULL;
    struct dns_opt_rr_t *rr_data;
    char *name;
    int i;
    int response_count;

    header = (struct dns_t *)packet;
    recv_ident = ntohs(header->id);

    /* make sure the id field in this packet matches our request */
    if ( recv_ident < ident || recv_ident - ident > count ) {
	Log(LOG_WARNING, "Incoming DNS packet with invalid ID number");
	return;
    }

    index = recv_ident - ident;
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
			process_opt_rr((char*)(rr_data + 1), &info[index]);
		    }
		    break;

		case 46: /* RRSIG */
		    info[index].dnssec_response = 1;
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
    info[index].delay = DIFF_TV_US(*now, info[index].time_sent);
}



/*
 *
 */
static void harvest(struct socket_t *sockets, uint16_t ident, int wait,
	int count, struct info_t info[], struct opt_t *opt) {

    char packet[opt->udp_payload_size];
    struct sockaddr_in6 addr;
    struct timeval now;

    while ( get_packet(sockets, packet, opt->udp_payload_size,
                (struct sockaddr *)&addr, &wait, &now) ) {
	process_packet(packet, ident, &now, count, info);
    }
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
    if ( opt->dnssec || opt->nsid ) {
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
    if ( opt->dnssec || opt->nsid ) {
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
    if ( opt->dnssec || opt->nsid ) {
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
static void send_packet(struct socket_t *sockets, uint16_t seq, uint16_t ident,
	struct addrinfo *dest, int count, struct info_t info[],
	struct opt_t *opt) {

    int sock;
    struct addrinfo tmpdst;
    int delay;
    char *qbuf;

    /* make a copy of the destination so we can modify the port */
    memcpy(&tmpdst, dest, sizeof(struct addrinfo));

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
	    sock = sockets->socket;
	    ((struct sockaddr_in*)tmpdst.ai_addr)->sin_port = htons(53);
	    break;
	case AF_INET6:
	    sock = sockets->socket6;
	    ((struct sockaddr_in6*)tmpdst.ai_addr)->sin6_port = htons(53);
	    break;
	default:
	    Log(LOG_WARNING, "Unknown address family: %d", dest->ai_family);
	    return;
    };

    if ( sock < 0 ) {
	Log(LOG_WARNING, "Unable to test to %s, socket wasn't opened",
                dest->ai_canonname);
	return;
    }

    qbuf = create_dns_query(seq + ident, &(info[seq].query_length), opt);

    while ( (delay = delay_send_packet(sock, qbuf, info[seq].query_length,
                    &tmpdst, &(info[seq].time_sent))) > 0 ) {
	harvest(sockets, ident, delay, count, info, opt);
    }

    if ( delay < 0 ) {
        /*
         * mark this as done if the packet failed to send properly, we don't
         * want to wait for a response that will never arrive.
         */
        memset(&(info[seq].time_sent), 0, sizeof(struct timeval));
        info[seq].reply = 1;
    }

    free(qbuf);
}



/*
 *
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
 *
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
 *
 */
static Amplet2__Dns__Item* report_destination(struct info_t *info) {

    Amplet2__Dns__Item *item =
        (Amplet2__Dns__Item*)malloc(sizeof(Amplet2__Dns__Item));

    /* fill the report item with results of a test */
    amplet2__dns__item__init(item);
    item->has_family = 1;
    item->family = info->addr->ai_family;
    item->name = address_to_name(info->addr);
    item->has_query_length = 1;
    item->query_length = info->query_length;
    item->has_address = copy_address_to_protobuf(&item->address, info->addr);

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

        /* possible instance name from NSID OPT RR */
        if ( strlen(info->response) > 0 ) {
            item->instance = info->response;
        } else {
            item->instance = NULL;
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
        item->instance = NULL;
    }

    Log(LOG_DEBUG, "dns result: %dus\n", item->has_rtt ? (int)item->rtt : -1);

    return item;
}



/*
 *
 */
static void report_results(struct timeval *start_time, int count,
	struct info_t info[], struct opt_t *opt) {

    int i;
    void *buffer;
    int len = 0;

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
    len = amplet2__dns__report__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__dns__report__pack(&msg, buffer);

    /* send the packed report object */
    report(AMP_TEST_DNS, (uint64_t)start_time->tv_sec, (void*)buffer, len);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < count; i++ ) {
        if ( reports[i]->flags ) {
            free(reports[i]->flags);
        }
        free(reports[i]);
    }

    free(reports);
    free(buffer);
}



/*
 *
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
 *
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
 *
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
 *
 */
static char *get_query_class_string(uint16_t query_class) {
    switch ( query_class ) {
	case 0x01: return "IN";
	default: return "unknown";
    };
}



/*
 *
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
 *
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
 *
 */
static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [-rsn] [-q query] [-t type] [-c class]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -q <query>\tQuery string (eg the hostname to look up)\n");
    fprintf(stderr, "  -t <type>\tRecord type to search for (default: A)\n");
    fprintf(stderr, "  -c <class>\tClass type to search for (default: IN)\n");
    fprintf(stderr, "  -z <size>\tUDP payload size (default: 4096)\n");
    fprintf(stderr, "  -p <ms>\tMaximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -r\t\tAllow recursive queries (default: false)\n");
    fprintf(stderr, "  -s\t\tUse DNSSEC (default: false)\n");
    fprintf(stderr, "  -n\t\tDo NSID query (default: false)\n");
}



/*
 *
 */
static void version(char *prog) {
    fprintf(stderr, "%s, amplet version %s, protocol version %d\n", prog,
            PACKAGE_STRING, AMP_DNS_TEST_VERSION);
}



/*
 * Reimplementation of the DNS2 test from AMP
 *
 * TODO check that all the random macros used for values are actually needed
 * TODO get useful errors into the log strings
 * TODO get test name into log strings
 * TODO logging will need more work - the log level won't be set.
 * TODO const up the dest arguments so cant be changed?
 */
int run_dns(int argc, char *argv[], int count, struct addrinfo **dests) {
    int opt;
    struct opt_t options;
    struct timeval start_time;
    struct info_t *info;
    struct socket_t sockets;
    int dest;
    uint16_t ident;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    int local_resolv;

    Log(LOG_DEBUG, "Starting DNS test");

    /* set some sensible defaults */
    options.query_string = NULL;
    options.query_type = 0x01;
    options.query_class = 0x01;
    options.udp_payload_size = 4096; /* dig defaults to 4096 bytes */
    options.recurse = 0;
    options.dnssec = 0;
    options.nsid = 0;
    options.perturbate = 0;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;
    local_resolv = 0;

    while ( (opt = getopt_long(argc, argv, "hvI:q:t:c:z:rsn4:6:",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4': sourcev4 = get_numeric_address(optarg, NULL); break;
            case '6': sourcev6 = get_numeric_address(optarg, NULL); break;
            case 'I': device = optarg; break;
	    case 'q': options.query_string = strdup(optarg); break;
	    case 't': options.query_type = get_query_type(optarg); break;
	    case 'c': options.query_class = get_query_class(optarg); break;
	    case 'z': options.udp_payload_size = atoi(optarg); break;
	    case 'p': options.perturbate = atoi(optarg); break;
	    case 'r': options.recurse = 1; break;
	    case 's': options.dnssec = 1; break;
	    case 'n': options.nsid = 1; break;
            case 'v': version(argv[0]); exit(0);
	    case 'h':
	    default: usage(argv[0]); exit(0);
	};
    }

    assert(options.query_string);
    assert(strlen(options.query_string) < MAX_DNS_NAME_LEN);
    assert(options.query_type > 0);
    assert(options.query_class > 0);
    assert(options.udp_payload_size > 512);

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
            return -1;
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
    if ( options.perturbate ) {
	int delay;
	delay = options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		options.perturbate, delay);
	usleep(delay);
    }

    if ( !open_sockets(&sockets) ) {
	Log(LOG_ERR, "Unable to open sockets, aborting test");
	free(options.query_string);
	exit(-1);
    }

    if ( set_default_socket_options(&sockets) < 0 ) {
        Log(LOG_ERR, "Failed to set default socket options, aborting test");
        exit(-1);
    }

    if ( device && bind_sockets_to_device(&sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw ICMP socket to device, aborting test");
        exit(-1);
    }

    if ( (sourcev4 || sourcev6) &&
            bind_sockets_to_address(&sockets, sourcev4, sourcev6) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw ICMP socket to address, aborting test");
        exit(-1);
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	free(options.query_string);
	exit(-1);
    }

    /* use part of the current time as an identifier value */
    ident = (uint16_t)start_time.tv_usec;

    /* allocate space to store information about each request sent */
    info = (struct info_t *)malloc(sizeof(struct info_t) * count);
    memset(info, 0, sizeof(struct info_t) * count);

    /* send a test packet to each destination */
    for ( dest = 0; dest < count; dest++ ) {
	send_packet(&sockets, dest, ident, dests[dest], count, info, &options);
    }

    /*
     * harvest results - try with a short timeout to start with, so maybe we
     * can avoid doing the long wait later
     */
    harvest(&sockets, ident, LOSS_TIMEOUT / 100, count, info, &options);

    /* check if all expected responses have been received */
    for ( dest = 0; dest < count && info[dest].reply; dest++ ) {
	/* nothing */
    }

    /* if not, then call harvest again with the full timeout */
    if ( dest < count ) {
	harvest(&sockets, ident, LOSS_TIMEOUT, count, info, &options);
    }

    if ( sockets.socket > 0 ) {
	close(sockets.socket);
    }

    if ( sockets.socket6 > 0 ) {
	close(sockets.socket6);
    }

    if ( sourcev4 ) {
        freeaddrinfo(sourcev4);
    }

    if ( sourcev6 ) {
        freeaddrinfo(sourcev6);
    }

    /* send report */
    report_results(&start_time, count, info, &options);

    free(options.query_string);
    free(info);

    /* free any addresses we've had to make ourselves */
    if ( local_resolv && dests ) {
        while ( count > 0 ) {
            freeaddrinfo(dests[count-1]);
            count--;
        }
        free(dests);
    }

    return 0;
}



/*
 * Print DNS test results to stdout, nicely formatted for the standalone test.
 * Tries to look a little bit similar to the output of dig, but with fewer
 * lines of output per server.
 */
void print_dns(void *data, uint32_t len) {
    Amplet2__Dns__Report *msg;
    Amplet2__Dns__Item *item;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(data != NULL);

    /* unpack all the data */
    msg = amplet2__dns__report__unpack(NULL, len, data);

    assert(msg);
    assert(msg->header);

    /* print global configuration options */
    printf("\n");
    printf("AMP dns test, %zu destinations, %s %s %s",
	    msg->n_reports, msg->header->query,
	    get_query_class_string(msg->header->query_class),
	    get_query_type_string(msg->header->query_type));
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
            printf(" (%s) no response\n", addrstr);
            continue;
        }

        /* TODO Suppress instance name if it's the same as the ampname? */
        if ( item->instance ) {
            printf(" (%s,%s)", addrstr, item->instance);
        } else {
            printf(" (%s)", addrstr);
        }
        printf(" %dus", item->rtt);
	printf("\n");

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

	printf("QUERY: 1, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		item->total_answer, item->total_authority,
		item->total_additional);
	printf("\n");
    }

    amplet2__dns__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
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

void amp_test_report_results(struct timeval *start_time, int count,
	struct info_t info[], struct opt_t *opt) {
    report_results(start_time, count, info, opt);
}

#endif
