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
    {"ipv4", required_argument, 0, '4'},
    {"ipv6", required_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {NULL, 0, 0, 0}
};



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
static int process_ipv4_packet(char *packet, uint32_t bytes, uint16_t ident,
	struct timeval now, int count, struct info_t info[]) {

    struct iphdr *ip;
    struct icmphdr *icmp;
    uint16_t seq;

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
	return icmp_error(packet, bytes, ident, info);
    }

    /* if it is an echo reply but the id doesn't match then it's not ours */
    if ( ntohs(icmp->un.echo.id ) != ident ) {
        Log(LOG_DEBUG, "Bad ident (got %d, expected %d)",
                ntohs(icmp->un.echo.id), ident);
	return -1;
    }

    /* check the sequence number is less than the maximum number of requests */
    seq = ntohs(icmp->un.echo.sequence);
    if ( seq > count ) {
        Log(LOG_DEBUG, "Bad sequence number\n");
	return -1;
    }

    /* check that the magic value in the reply matches what we expected */
    //if ( *(uint16_t*)&packet[sizeof(struct iphdr)+sizeof(struct icmphdr)] !=
    if ( *(uint16_t*)(((char *)packet)+(ip->ihl<< 2)+sizeof(struct icmphdr)) !=
	    info[seq].magic ) {
        Log(LOG_DEBUG, "Bad magic value");
	return -1;
    }

    /* reply is good, record the round trip time */
    info[seq].reply = 1;
    info[seq].delay = DIFF_TV_US(now, info[seq].time_sent);

    Log(LOG_DEBUG, "Good ICMP ECHOREPLY");
    return 0;
}



/*
 * XXX this won't record errors for ipv6 packets but the ipv4 test will. This
 * is the same behaviour as the original icmp test, but is it really what we
 * want? Should record errors for both protocols, or neither?
 */
static int process_ipv6_packet(char *packet, uint32_t bytes, uint16_t ident,
	struct timeval now, int count, struct info_t info[]) {

    struct icmp6_hdr *icmp;
    uint16_t seq;

    if ( bytes < sizeof(struct icmp6_hdr) ) {
        return -1;
    }

    /* any icmpv6 packets we get have the outer ipv6 header stripped */
    icmp = (struct icmp6_hdr *)packet;
    seq = ntohs(icmp->icmp6_seq);

    /* sanity check the various fields of the icmp header */
    if ( icmp->icmp6_type != ICMP6_ECHO_REPLY ||
	    ntohs(icmp->icmp6_id) != ident ||
	    seq > count ) {
	return -1;
    }

    /* check that the magic value in the reply matches what we expected */
    if ( *(uint16_t*)(((char*)packet) + sizeof(struct icmp6_hdr)) !=
	    info[seq].magic ) {
	return -1;
    }

    /* reply is good, record the round trip time */
    info[seq].reply = 1;
    info[seq].delay = DIFF_TV_US(now, info[seq].time_sent);

    Log(LOG_DEBUG, "Good ICMP6 ECHOREPLY");
    return 0;
}



/*
 *
 */
static void harvest(struct socket_t *raw_sockets, uint16_t ident, int wait,
	int outstanding, int count, struct info_t info[]) {

    char packet[RESPONSE_BUFFER_LEN];
    struct timeval now;
    struct iphdr *ip;
    int result;
    ssize_t bytes;

    /*
     * Read packets until we hit the timeout, or we have all we expect.
     * Note that wait is reduced by get_packet(), and that the buffer is
     * only big enough for the data from the packet that we require - the
     * excess bytes will be discarded.
     */
    while ( (bytes = get_packet(raw_sockets, packet, RESPONSE_BUFFER_LEN,
                    NULL, &wait, &now)) > 0 ) {
	/*
	 * this check isn't as nice as it could be - should we explicitly ask
	 * for the icmp6 header to be returned so we can be sure we are
	 * checking the right things?
	 */
        ip = (struct iphdr*)packet;
        switch ( ip->version ) {
	    case 4: result =
                        process_ipv4_packet(packet, bytes, ident, now, count,
                                info);
		    break;
	    default: /* unless we ask we don't have an ipv6 header here */
		    result =
                        process_ipv6_packet(packet, bytes, ident, now, count,
                                info);
		    break;
	};

        /*
         * Decrement the number of outstanding results only if we know how
         * many results we are still waiting on.
         */
        if ( outstanding > 0 && result == 0 ) {
            outstanding--;
            if ( outstanding == 0 ) {
                return;
            }
        }
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
		    dest, opt->inter_packet_delay,
                    &(info[seq].time_sent))) > 0 ) {
	/* check for responses while we wait out the interpacket delay */
	harvest(raw_sockets, ident, delay, -1, count, info);
    }

    if ( delay < 0 ) {
        /*
         * mark this as done if the packet failed to send properly, we don't
         * want to wait for a response that will never arrive.
         */
        info[seq].reply = 1;
        memset(&(info[seq].time_sent), 0, sizeof(struct timeval));
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
static Amplet2__Icmp__Item* report_destination(struct info_t *info) {

    Amplet2__Icmp__Item *item =
        (Amplet2__Icmp__Item*)malloc(sizeof(Amplet2__Icmp__Item));

    /* fill the report item with results of a test */
    amplet2__icmp__item__init(item);
    item->has_family = 1;
    item->family = info->addr->ai_family;
    item->name = address_to_name(info->addr);
    item->has_address = copy_address_to_protobuf(&item->address, info->addr);

    /* TODO do we want to truncate to milliseconds like the old test? */
    if ( info->reply && info->time_sent.tv_sec > 0 &&
            (info->err_type == ICMP_REDIRECT ||
             (info->err_type == 0 && info->err_code == 0)) ) {
        //printf("%dms ", (int)((info[i].delay/1000.0) + 0.5));
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
 *
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
            "                [-I interface] [-4 sourcev4] [-6 sourcev6]\n"
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
 * Reimplementation of the ICMP test from AMP
 *
 * TODO get useful errors into the log strings
 * TODO get test name into log strings
 * TODO logging will need more work - the log level won't be set.
 * TODO const up the dest arguments so cant be changed?
 */
amp_test_result_t* run_icmp(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    struct opt_t options;
    struct timeval start_time;
    struct socket_t raw_sockets;
    struct info_t *info;
    int dest;
    uint16_t ident;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    int outstanding;
    amp_test_result_t *result;

    Log(LOG_DEBUG, "Starting ICMP test");

    /* set some sensible defaults */
    options.dscp = DEFAULT_DSCP_VALUE;
    options.inter_packet_delay = MIN_INTER_PACKET_DELAY;
    options.packet_size = DEFAULT_ICMP_ECHO_REQUEST_LEN;
    options.random = 0;
    options.perturbate = 0;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "p:rs:I:Q:Z:4:6:hvx",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4': sourcev4 = get_numeric_address(optarg, NULL); break;
            case '6': sourcev6 = get_numeric_address(optarg, NULL); break;
            case 'I': device = optarg; break;
            case 'Q': if ( parse_dscp_value(optarg, &options.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(-1);
                      }
                      break;
            case 'Z': options.inter_packet_delay = atoi(optarg); break;
            case 'p': options.perturbate = atoi(optarg); break;
            case 'r': options.random = 1; break;
            case 's': options.packet_size = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(0);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h':
            default: usage(); exit(0);
	};
    }

    if ( count < 1 ) {
        usage();
        exit(0);
    }

    /* pick a random packet size within allowable boundaries */
    if ( options.random ) {
	options.packet_size = MIN_PACKET_LEN +
	    (int)((1500 - MIN_PACKET_LEN) * (random()/(RAND_MAX+1.0)));
	Log(LOG_DEBUG, "Setting packetsize to random value: %d\n",
		options.packet_size);
    }

    /* make sure that the packet size is big enough for our data */
    if ( options.packet_size < MIN_PACKET_LEN ) {
	Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
		options.packet_size, MIN_PACKET_LEN);
	options.packet_size = MIN_PACKET_LEN;
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

    if ( set_default_socket_options(&raw_sockets) < 0 ) {
        Log(LOG_ERR, "Failed to set default socket options, aborting test");
        exit(-1);
    }

    if ( set_dscp_socket_options(&raw_sockets, options.dscp) < 0 ) {
        Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
        exit(-1);
    }

    if ( device && bind_sockets_to_device(&raw_sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw ICMP socket to device, aborting test");
        exit(-1);
    }

    if ( (sourcev4 || sourcev6) &&
            bind_sockets_to_address(&raw_sockets, sourcev4, sourcev6) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw ICMP socket to address, aborting test");
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
     * Check if all expected responses have been received, we might have got
     * them all during the interpacket wait or they may have failed to send.
     */
    outstanding = 0;
    for ( dest = 0; dest < count; dest++ ) {
        if ( !info[dest].reply ) {
            outstanding++;
        }
    }

    /* If there are any outstanding reponses then we need to wait for them. */
    if ( outstanding > 0 ) {
        harvest(&raw_sockets, ident, LOSS_TIMEOUT, outstanding, count, info);
    }

    if ( raw_sockets.socket > 0 ) {
	close(raw_sockets.socket);
    }

    if ( raw_sockets.socket6 > 0 ) {
	close(raw_sockets.socket6);
    }

    if ( sourcev4 ) {
        freeaddrinfo(sourcev4);
    }

    if ( sourcev6 ) {
        freeaddrinfo(sourcev6);
    }

    /* send report */
    result = report_results(&start_time, count, info, &options);

    free(info);

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
int amp_test_process_ipv4_packet(char *packet, uint32_t bytes, uint16_t ident,
	struct timeval now, int count, struct info_t info[]) {
    return process_ipv4_packet(packet, bytes, ident, now, count, info);
}

amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt) {
    return report_results(start_time, count, info, opt);
}
#endif
