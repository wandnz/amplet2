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
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <string.h>

//TODO rename files and headers better?
#include "testlib.h"
#include "icmp.h"


/*
 * TODO collect more information than what the original icmp test did.
 * Things like rtt could be interesting to track.
 */


/*
 * Calculate the icmp header checksum. Based on the checkSum() function found
 * in AMP at src/lib/checksum.c
 */
static int checksum(uint16_t *packet, int size) {
    register uint16_t answer;
    register uint64_t sum;
    uint16_t odd;

    sum = 0;
    odd = 0;

    while ( size > 1 ) {
	sum += *packet++;
	size -= 2;
    }

    /* mop up an odd byte if needed */
    if ( size == 1 ) {
	*(unsigned char *)(&odd) = *(unsigned char *)packet;
	sum += odd;
    }

    sum = (sum >> 16) + (sum & 0xffff);	    /* add high 16 to low 16 */
    sum += (sum >> 16);			    /* add carry */
    answer = ~sum;			    /* ones complement, truncate */

    return answer;
}



/*
 * Check an icmp error to determine if it is in response to a packet we have
 * sent. If it is then the error needs to be recorded.
 */
static void icmp_error(char *packet, uint16_t ident, struct info_t info[]) {
    struct iphdr *ip, *embed_ip;
    struct icmphdr *icmp, *embed_icmp;
    uint16_t seq;

    ip = (struct iphdr *)packet;

    assert(ip->version == 4);
    assert(ip->ihl >= 5);

    icmp = (struct icmphdr *)(packet + (ip->ihl << 2));

    /*
     * make sure there is enough room in this packet to entertain the
     * possibility of having embedded data - at least enough space for
     * 2 ip headers (one of known length), 2 icmp headers.
     */
    if ( ip->tot_len < (ip->ihl << 2) + sizeof(struct iphdr) +
	    (sizeof(struct icmphdr) * 2) ) {
	Log(LOG_DEBUG, "ICMP reply too small for embedded packet data");
	return;
    }

    /* get the embedded ip header */
    embed_ip = (struct iphdr *)(packet + ((ip->ihl << 2) +
		sizeof(struct icmphdr)));

    /* obviously not a response to our test, return */
    if ( embed_ip->version != 4 || embed_ip->protocol != IPPROTO_ICMP ) {
	return;
    }

    /* get the embedded icmp header */
    embed_icmp = (struct icmphdr*)(((char *)embed_ip) + (embed_ip->ihl << 2));

    /* make sure the embedded header looks like one of ours */
    if ( embed_icmp->type > NR_ICMP_TYPES ||
	    embed_icmp->type != ICMP_ECHO || embed_icmp->code != 0 ||
	    ntohs(embed_icmp->un.echo.id) != ident) {
	return;
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

    return;
}



/*
 * Process an ICMPv4 packet to check if it is an ICMP ECHO REPLY in response to
 * a request we have sent. If so then record the time it took to get the reply.
 */
static void process_ipv4_packet(char *packet, uint16_t ident,
	struct timeval now, int count, struct info_t info[]) {

    struct iphdr *ip;
    struct icmphdr *icmp;
    uint16_t seq;

    /* any icmpv4 packets we get have full headers attached */
    ip = (struct iphdr *)packet;

    assert(ip->version == 4);
    assert(ip->ihl >= 5);

    icmp = (struct icmphdr *)(packet + (ip->ihl << 2));

    /* if it isn't an echo reply it could still be an error for us */
    if ( icmp->type != ICMP_ECHOREPLY ) {
	icmp_error(packet, ident, info);
	return;
    }

    /* if it is an echo reply but the id doesn't match then it's not ours */
    if ( ntohs(icmp->un.echo.id ) != ident ) {
	return;
    }

    /* check the sequence number is less than the maximum number of requests */
    seq = ntohs(icmp->un.echo.sequence);
    if ( seq > count ) {
	return;
    }

    /* check that the magic value in the reply matches what we expected */
    //if ( *(uint16_t*)&packet[sizeof(struct iphdr)+sizeof(struct icmphdr)] !=
    if ( *(uint16_t*)(((char *)packet)+(ip->ihl<< 2)+sizeof(struct icmphdr)) !=
	    info[seq].magic ) {
	return;
    }

    /* reply is good, record the round trip time */
    info[seq].reply = 1;
    info[seq].delay = DIFF_TV_US(now, info[seq].time_sent);
}



/*
 * XXX this won't record errors for ipv6 packets but the ipv4 test will. This
 * is the same behaviour as the original icmp test, but is it really what we
 * want? Should record errors for both protocols, or neither?
 */
static void process_ipv6_packet(char *packet, uint16_t ident,
	struct timeval now, int count, struct info_t info[]) {

    struct icmp6_hdr *icmp;
    uint16_t seq;

    /* any icmpv6 packets we get have the outer ipv6 header stripped */
    icmp = (struct icmp6_hdr *)packet;
    seq = ntohs(icmp->icmp6_seq);

    /* sanity check the various fields of the icmp header */
    if ( icmp->icmp6_type != ICMP6_ECHO_REPLY ||
	    ntohs(icmp->icmp6_id) != ident ||
	    seq > count ) {
	return;
    }

    /* check that the magic value in the reply matches what we expected */
    if ( *(uint16_t*)(((char*)packet) + sizeof(struct icmp6_hdr)) !=
	    info[seq].magic ) {
	return;
    }

    /* reply is good, record the round trip time */
    info[seq].reply = 1;
    info[seq].delay = DIFF_TV_US(now, info[seq].time_sent);
}



/*
 *
 */
static void harvest(struct socket_t *raw_sockets, uint16_t ident, int wait,
	int count, struct info_t info[]) {

    char packet[2048]; //XXX can we be sure of a max size for recv packets?
    struct timeval now;
    struct sockaddr_in6 addr;

    /* read packets until we hit the timeout, or we have all we expect.
     * Note that wait is reduced by get_packet()
     */
    while ( get_packet(raw_sockets, packet, 1024, (struct sockaddr*)&addr,
		&wait) ) {
	gettimeofday(&now, NULL);

	/*
	 * this check isn't as nice as it could be - should we explicitly ask
	 * for the icmp6 header to be returned so we can be sure we are
	 * checking the right things?
	 */
	switch ( ((struct iphdr*)packet)->version ) {
	    case 4: process_ipv4_packet(packet, ident, now, count, info);
		    break;
	    default: /* unless we ask we don't have an ipv6 header here */
		    process_ipv6_packet(packet, ident, now, count, info);
		    break;
	};
    }
}



/*
 * Construct and send an icmp echo request packet.
 */
static void send_packet(struct socket_t *raw_sockets, int seq, uint16_t ident,
	struct addrinfo *dest, int count, struct info_t info[],
	struct opt_t *opt) {

    struct icmphdr *icmp;
    char packet[opt->packet_size];
    int sock;
    int h_len;
    uint16_t magic;
    int delay;

    /* both icmp and icmpv6 echo request have the same structure */
    memset(packet, 0, sizeof(packet));
    icmp = (struct icmphdr *)packet;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(ident);
    icmp->un.echo.sequence = htons(seq);
    /* set data portion with random number */
    magic = rand();
    memcpy(&packet[sizeof(struct icmphdr)], &magic, sizeof(magic));

    /* save information about this packet so we can track the response */
    info[seq].addr = dest;
    info[seq].reply = 0;
    info[seq].err_type = 0;
    info[seq].err_code = 0;
    info[seq].ttl = 0;
    info[seq].magic = magic;

    switch ( dest->ai_family ) {
	case AF_INET:
	    icmp->type = ICMP_ECHO;
	    sock = raw_sockets->socket;
	    h_len = sizeof(struct iphdr);
	    icmp->checksum = checksum((uint16_t*)packet,
		    opt->packet_size - h_len);
	    break;
	case AF_INET6:
	    icmp->type = ICMP6_ECHO_REQUEST;
	    sock = raw_sockets->socket6;
	    h_len = sizeof(struct ip6_hdr);
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

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, packet, opt->packet_size-h_len,
		    dest)) > 0 ) {
	/* check for responses while we wait out the interpacket delay */
	harvest(raw_sockets, ident, delay, count, info);
    }

    if ( delay < 0 ) {
        /*
         * mark this as done if the packet failed to send properly, we don't
         * want to wait for a response that will never arrive.
         */
        info[seq].reply = 1;
        memset(&(info[seq].time_sent), 0, sizeof(struct timeval));
    } else {
        /* record the time the packet was sent */
        gettimeofday(&(info[seq].time_sent), NULL);
    }
}



/*
 * Open the raw ICMP and ICMPv6 sockets used for this test and configure
 * appropriate filters for the ICMPv6 socket to only receive echo replies.
 */
static int open_sockets(struct socket_t *raw_sockets) {
    if ( (raw_sockets->socket =
		socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMP");
    }

    if ( (raw_sockets->socket6 =
		socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6))<0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMPv6");
    } else {
	/* configure ICMPv6 filters to only pass through ICMPv6 echo reply */
	struct icmp6_filter filter;
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
	if ( setsockopt(raw_sockets->socket6, SOL_ICMPV6, ICMP6_FILTER,
		    &filter, sizeof(struct icmp6_filter)) < 0 ) {
	    Log(LOG_WARNING, "Could not set ICMPv6 filter");
	}
    }

    /* make sure at least one type of socket was opened */
    if ( raw_sockets->socket < 0 && raw_sockets->socket6 < 0 ) {
	return 0;
    }

    return 1;
}



/*
 *
 */
static void report_results(struct timeval *start_time, int count,
	struct info_t info[], struct opt_t *opt) {

    int i;
    char *buffer;
    struct icmp_report_header_t *header;
    struct icmp_report_item_t *item;
    int len, maxlen;

    Log(LOG_DEBUG, "Building icmp report, count:%d, psize:%d, rand:%d\n",
	    count, opt->packet_size, opt->random);
    /* XXX could this get too large? */
    /*
     * Allocate space for all our results:
     * 1 main header, 1 report item + 255 bytes of max ampname size per test
     */
    maxlen = (sizeof(struct icmp_report_header_t)) +
        (count * sizeof(struct icmp_report_item_t)) +
        (count * MAX_STRING_FIELD);
    buffer = malloc(maxlen);
    memset(buffer, 0, maxlen);

    /* single header at the start of the buffer describes the test options */
    header = (struct icmp_report_header_t *)buffer;
    header->version = AMP_ICMP_TEST_VERSION;
    header->packet_size = opt->packet_size;
    header->random = opt->random;
    header->count = count;
    len = sizeof(struct icmp_report_header_t);

    /* add results for all the destinations */
    for ( i = 0; i < count; i++ ) {
        char *ampname = address_to_name(info[i].addr);
        assert(ampname);
        assert(strlen(ampname) < MAX_STRING_FIELD);

        /* fill the report item with results of a test */
        item = (struct icmp_report_item_t *)(buffer + len);
	item->err_type = info[i].err_type;
	item->err_code = info[i].err_code;
	item->family = info[i].addr->ai_family;
	item->ttl = info[i].ttl;

	switch ( item->family ) {
	    case AF_INET:
		memcpy(item->address,
			&((struct sockaddr_in*)
			    info[i].addr->ai_addr)->sin_addr,
			sizeof(struct in_addr));
		break;
	    case AF_INET6:
		memcpy(item->address,
			&((struct sockaddr_in6*)
			    info[i].addr->ai_addr)->sin6_addr,
			sizeof(struct in6_addr));
		break;
	    default:
		Log(LOG_WARNING, "Unknown address family %d\n", item->family);
		memset(item->address, 0, sizeof(item->address));
		break;
	};

	/* TODO do we want to truncate to milliseconds like the old test? */
	if ( info[i].reply && info[i].time_sent.tv_sec > 0 &&
                (info[i].err_type == ICMP_REDIRECT ||
                 (info[i].err_type == 0 && info[i].err_code == 0)) ) {
	    //printf("%dms ", (int)((info[i].delay/1000.0) + 0.5));
	    item->rtt = info[i].delay;
	} else {
	    item->rtt = -1;
	}

        len += sizeof(struct icmp_report_item_t);

        /* add variable length ampname onto the buffer, after the report item */
        item->namelen = strlen(ampname) + 1;
        strncpy(buffer + len, ampname, MAX_STRING_FIELD);
        len += item->namelen;
	Log(LOG_DEBUG, "icmp result %d: %dus, %d/%d\n", i, item->rtt,
		item->err_type, item->err_code);
    }

    report(AMP_TEST_ICMP, (uint64_t)start_time->tv_sec, (void*)buffer, len);
    free(buffer);
}



/*
 *
 */
static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [-r] [-p perturbate] [-s packetsize]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -r\t\tUse a random packet size for each test\n");
    fprintf(stderr, "  -p <ms>\tMaximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -s <bytes>\tFixed packet size to use for each test\n");
}



/*
 * Reimplementation of the ICMP test from AMP
 *
 * TODO get useful errors into the log strings
 * TODO get test name into log strings
 * TODO logging will need more work - the log level won't be set.
 * TODO const up the dest arguments so cant be changed?
 */
int run_icmp(int argc, char *argv[], int count, struct addrinfo **dests) {
    int opt;
    struct opt_t options;
    struct timeval start_time;
    struct socket_t raw_sockets;
    struct info_t *info;
    int dest;
    uint16_t ident;

    Log(LOG_DEBUG, "Starting ICMP test");

    /* set some sensible defaults */
    options.packet_size = DEFAULT_ICMP_ECHO_REQUEST_LEN;
    options.random = 0;
    options.perturbate = 0;

    while ( (opt = getopt(argc, argv, "hp:rs:S:")) != -1 ) {
	switch ( opt ) {
	    case 'p': options.perturbate = atoi(optarg); break;
	    case 'r': options.random = 1; break;
	    case 's': options.packet_size = atoi(optarg); break;
	    case 'h':
	    default: usage(argv[0]); exit(0);
	};
    }

    /* pick a random packet size within allowable boundaries */
    if ( options.random ) {
	options.packet_size = MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN +
	    (int)((1500 - IP_HEADER_LEN - MIN_ICMP_ECHO_REQUEST_LEN)
		    * (random()/(RAND_MAX+1.0)));
	Log(LOG_DEBUG, "Setting packetsize to random value: %d\n",
		options.packet_size);
    }

    /* make sure that the packet size is big enough for our data */
    if ( options.packet_size < MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN ) {
	Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
		options.packet_size,
		MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN);
	options.packet_size = MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN;
    }

    /* delay the start by a random amount of perturbate is set */
    if ( options.perturbate ) {
	int delay;
	delay = options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		options.perturbate, delay);
	usleep(delay);
    }

    if ( !open_sockets(&raw_sockets) ) {
	Log(LOG_ERR, "Unable to open raw ICMP sockets, aborting test");
	exit(-1);
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(-1);
    }

    /* use part of the current time as an identifier value */
    ident = (uint16_t)start_time.tv_usec;

    /* allocate space to store information about each request sent */
    info = (struct info_t *)malloc(sizeof(struct info_t) * count);

    /* send a test packet to each destination */
    for ( dest = 0; dest < count; dest++ ) {
	send_packet(&raw_sockets, dest, ident, dests[dest], count, info,
		&options);
    }

    /*
     * harvest results - try with a short timeout to start with, so maybe we
     * can avoid doing the long wait later
     */
    harvest(&raw_sockets, ident, LOSS_TIMEOUT / 100, count, info);

    /* check if all expected responses have been received */
    for ( dest = 0; dest < count && info[dest].reply; dest++ ) {
	/* nothing */
    }

    /* if not, then call harvest again with the full timeout */
    if ( dest < count ) {
	harvest(&raw_sockets, ident, LOSS_TIMEOUT, count, info);
    }

    if ( raw_sockets.socket > 0 ) {
	close(raw_sockets.socket);
    }

    if ( raw_sockets.socket6 > 0 ) {
	close(raw_sockets.socket6);
    }

    /* send report */
    report_results(&start_time, count, info, &options);

    free(info);

    return 0;
}



/*
 * Print icmp test results to stdout, nicely formatted for the standalone test
 */
void print_icmp(void *data, uint32_t len) {
    struct icmp_report_header_t *header = (struct icmp_report_header_t*)data;
    struct icmp_report_item_t *item;
    char addrstr[INET6_ADDRSTRLEN];
    int i, offset;
    char *ampname;

    assert(data != NULL);
    assert(len >= sizeof(struct icmp_report_header_t));
    assert(len >= sizeof(struct icmp_report_header_t) +
	    header->count * sizeof(struct icmp_report_item_t));
    assert(header->version == AMP_ICMP_TEST_VERSION);

    printf("\n");
    printf("AMP icmp test, %u destinations, %u byte packets ", header->count,
	    header->packet_size);
    if ( header->random ) {
	printf("(random size)\n");
    } else {
	printf("(fixed size)\n");
    }

    offset = sizeof(struct icmp_report_header_t);

    for ( i=0; i<header->count; i++ ) {
        item = (struct icmp_report_item_t*)(data + offset);
        offset += sizeof(struct icmp_report_item_t);

        ampname = (char *)data + offset;
        offset += item->namelen;
	printf("%s", ampname);

	inet_ntop(item->family, item->address, addrstr, INET6_ADDRSTRLEN);
	printf(" (%s)",	addrstr);

	if ( item->rtt < 0 ) {
	    if ( item->err_type == 0 ) {
		printf(" missing");
	    } else {
		printf(" error");
	    }
	} else {
	    printf(" %dus", item->rtt);
	}
	printf(" (%u/%u)\n", item->err_type, item->err_code);
    }
    printf("\n");
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_ICMP;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("icmp");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_icmp;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_icmp;

    return new_test;
}
