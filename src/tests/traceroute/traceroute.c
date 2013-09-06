#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
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
#include "traceroute.h"


/*
 * Fill out the IP and UDP header in the given data blob with the appropriate
 * values for our probes.
 */
static int build_ipv4_probe(void *packet, uint16_t packet_size, int id,
        int ttl, uint16_t ident, struct addrinfo *dest) {

    struct iphdr *ip;
    struct udphdr *udp;

    assert(packet);
    assert(packet_size >= MIN_TRACEROUTE_PROBE_LEN);

    ip = (struct iphdr *)packet;
    memset(ip, 0, sizeof(struct iphdr));

    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(packet_size);
    ip->id = htons(id);
    ip->ttl = ttl;
    ip->protocol = IPPROTO_UDP;
    ip->daddr = ((struct sockaddr_in *)dest->ai_addr)->sin_addr.s_addr;

    udp = (struct udphdr *)(packet + (ip->ihl << 2));
    udp->source = htons(ident);
    udp->dest = htons(TRACEROUTE_DEST_PORT);
    udp->len = htons(packet_size - ((ip->ihl << 2)));

    return packet_size;
}



/*
 * Fill out the body of the UDP packet in the given data blob with the
 * appropriate values for our probes.
 */
static int build_ipv6_probe(void *packet, uint16_t packet_size, int id,
        uint16_t ident, struct addrinfo *dest) {

    struct ipv6_body_t *ipv6_body;
    ipv6_body = (struct ipv6_body_t *)packet;
    ipv6_body->index = htons(id);
    ipv6_body->ident = htons(ident);
    ((struct sockaddr_in6 *)dest->ai_addr)->sin6_port =
        htons(TRACEROUTE_DEST_PORT);

    return packet_size;
}



/*
 * Send a single probe packet towards a destination with the given TTL.
 */
static void send_probe(struct socket_t *ip_sockets, int dest_id, int ttl,
        uint16_t ident, struct addrinfo *dest, struct info_t *info,
        struct opt_t *opt) {

    char packet[opt->packet_size];
    long int delay;
    uint16_t id;
    int sock;
    int length;

    memset(packet, 0, sizeof(packet));
    id = (ttl << 10) + dest_id;

    switch ( dest->ai_family ) {
        case AF_INET: {
            sock = ip_sockets->socket;
            length = build_ipv4_probe(packet, opt->packet_size, id, ttl,
                    ident, dest);
        } break;

        case AF_INET6: {
            sock = ip_sockets->socket6;
            setsockopt(sock, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
            length = build_ipv6_probe(packet, opt->packet_size, id,
                    ident, dest);
        } break;

        default:
	    Log(LOG_WARNING, "Unknown address family: %d", dest->ai_family);
	    return;
    };

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, packet, length, dest)) > 0 ) {
        usleep(delay);
    }

    /* record the time the packet was sent */
    if ( info != NULL ) {
        gettimeofday(&(info[dest_id].hop[ttl - 1].time_sent), NULL);
        info[dest_id].retry = 0;
    }
}



/*
 * Extract the index value that has been encoded into the IP ID field.
 */
static int get_index(struct iphdr *ip, int count) {
    uint16_t index;

    index = ntohs(ip->id);
    if ( (index & 0x3FF) >= count ) {
        /*
         * According to the original traceroute test:
         * some boxes are broken and byteswap the ip id field but
         * don't put it back before putting it into the end of the
         * icmp error. Check if swapping the byte order makes the
         * ip id match what we were expecting...
         */
        if ( (ip->id & 0x3FF) < count ) {
            return ip->id;
        }
        Log(LOG_DEBUG, "Bad index %d in embedded packet ignored", index&0x3FF);
        return -1;
    }

    return index;
}



/*
 *
 */
static int is_icmp4_error(struct iphdr *ip, struct icmphdr *icmp,
        struct iphdr *embedded_ip, struct udphdr *embedded_udp, uint16_t ident,
        int count, struct info_t *info) {

    int index;

    assert(ip);
    assert(icmp);
    assert(embedded_ip);
    assert(embedded_udp);

    /* source port doesn't match ours, this response is not for us */
    if ( ntohs(embedded_udp->source) != ident ) {
        return 1;
    }

    /* index doesn't match, we can't use this */
    if ( (index = get_index(embedded_ip, count)) < 0 ) {
        return 1;
    }
    index &= 0x3FF;

    /* Port unreachable is fine if it comes from the expected destination */
    if ( icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_PORT_UNREACH ) {
        /* check if this is a port unreachable for us or not */
        if ( ((struct sockaddr_in*)info[index].addr->ai_addr)->sin_addr.s_addr == ip->saddr ) {
            /* all good, no error */
            return 0;
        }
        /*
         * If it isn't then try again without waiting for a timeout. The
         * original traceroute test suggests this isn't too uncommon.
         */
        info[index].retry = 1;
        return 1;
    }

    /* TTL exceeded, this is fine */
    if ( icmp->type == ICMP_TIME_EXCEEDED ) {
        return 0;
    }

    /* it's some other error, record the type and code */
    info[index].err_type = icmp->type;
    info[index].err_code = icmp->code;

    /* stop probing if we get an error we can't really continue from */
    if ( icmp->type == ICMP_DEST_UNREACH || icmp->type == ICMP_PARAMETERPROB ) {
        info[index].done = 1;
    } else {
        info[index].retry = 1;
    }

    return 1;
}



/*
 *
 */
static void process_ipv4_packet(char *packet, struct timeval now,
        uint16_t ident, int count, struct info_t *info) {

    struct iphdr *ip;
    struct iphdr *embedded_ip;
    struct icmphdr *icmp;
    struct udphdr *embedded_udp;
    int index;
    int ttl;

    ip = (struct iphdr *)packet;
    assert(ip->version == 4);
    assert(ip->ihl >= 5);

    icmp = (struct icmphdr *)(packet + (ip->ihl << 2));

    /*
     * We can't do anything if there is no room in the response for an
     * embedded UDP packet. We need enough data for the IP header, ICMP
     * header, embedded IP header (that we initially sent, no options)
     * and the embedded UDP header (that we initially sent).
     */
    if ( ntohs(ip->tot_len) <
            (ip->ihl << 2) + sizeof(struct icmphdr) + sizeof(struct iphdr) +
            sizeof(struct udphdr) ) {
        Log(LOG_DEBUG, "Reponse too small for embedded data: %d bytes",
                ntohs(ip->tot_len));
        return;
    }

    /* make sure that what we have embedded is one of our UDP probes */
    embedded_ip = (struct iphdr *)(((char *)icmp) + sizeof(struct icmphdr));
    if ( embedded_ip->protocol != IPPROTO_UDP ) {
        return;
    }
    embedded_udp = (struct udphdr *)(((char *)embedded_ip) +
        (embedded_ip->ihl << 2));

    if ( is_icmp4_error(ip, icmp, embedded_ip, embedded_udp, ident, count,
                info) ) {
        return;
    }

    if ( (index = get_index(embedded_ip, count)) < 0 ) {
        return;
    }

    ttl = index >> 10;
    index &= 0x3FF;

    /* record the delay between sending this probe and getting a response */
    if ( info[index].hop[ttl - 1].delay == 0 ) {
        info[index].hop[ttl - 1].delay =
            DIFF_TV_US(now, info[index].hop[ttl - 1].time_sent);
    }

    /* if it's not an error we are expecting, record it and return */
    if ( icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) {
        info[index].err_type = icmp->type;
        info[index].err_code = icmp->code;
        return;
    }

    if ( HOP_REPLY(index, ttl) ) {
        Log(LOG_DEBUG, "Duplicate reply for hop %d from %s\n",
                info[index].ttl - 1, "XXX");
    } else {
        HOP_REPLY(index, ttl) = 1;
        HOP_ADDR(index, ttl) =
            (struct addrinfo *)malloc(sizeof(struct addrinfo));
        HOP_ADDR(index, ttl)->ai_addr =
            (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
        HOP_ADDR(index, ttl)->ai_family = AF_INET;
        HOP_ADDR(index, ttl)->ai_addrlen = sizeof(struct sockaddr_in);
        ((struct sockaddr_in *)HOP_ADDR(index, ttl)->ai_addr)->sin_addr.s_addr = ip->saddr;
        HOP_ADDR(index, ttl)->ai_canonname = NULL;
        HOP_ADDR(index, ttl)->ai_next = NULL;
    }

    if ( icmp->type == ICMP_DEST_UNREACH ) {
        if ( info[index].ttl == TRACEROUTE_FULL_PATH_PROBE_TTL ) {
            info[index].ttl = MAX_HOPS_IN_PATH - embedded_ip->ttl + 1;
        }
        info[index].done = 1;
        return;
    }

    if ( info[index].ttl >= MAX_HOPS_IN_PATH ) {
        info[index].done = 1;
    } else {
        /*
         * Only reset these counters if the response was on time, otherwise
         * we have already moved on and they are no longer related to this
         * hop. The only reason we have got this far was to record the address
         * and latency rather than ignoring this response packet entirely and
         * leaving a gap that could have been avoided.
         */
        if ( info[index].hop[ttl - 1].delay < LOSS_TIMEOUT ) {
            info[index].ttl++;
            info[index].attempts = 0;
            info[index].no_reply_count = 0;
        }
    }
}



/*
 *
 */
static void process_ipv6_packet(char *packet, struct sockaddr_in6 *addr,
        struct timeval now, uint16_t ident, int count, struct info_t *info) {

    struct icmp6_hdr *icmp6;
    struct ip6_hdr *embedded_ipv6;
    struct udphdr *embedded_udp;
    struct ipv6_body_t *ipv6_body;
    int index;
    int next_header;
    int ttl;

    /* we get an ICMPv6 header here, the IP header has been stripped already */
    icmp6 = (struct icmp6_hdr *)packet;

    /*
     * Make sure the response is of the right type, others can slip through
     * while the filter is being established.
     */
    if ( icmp6->icmp6_type != ICMP6_DST_UNREACH &&
            icmp6->icmp6_type != ICMP6_TIME_EXCEEDED ) {
        return;
    }

    /* the response is the right type so we should have an embedded packet */
    embedded_ipv6 = (struct ip6_hdr *)(icmp6 + 1);
    embedded_udp = (struct udphdr *)(embedded_ipv6 + 1);
    next_header = embedded_ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    /* if there is a fragment header then jump to the start of the fragment */
    if ( next_header == IPPROTO_FRAGMENT ) {
        /*
         * The first field in the fragment header (where embedded_udp currently
         * points) is the next header field for what the fragment contains. The
         * fragment itself starts directly after the 8 byte fragment header.
         */
        next_header = *(uint8_t*)embedded_udp;
        embedded_udp = (struct udphdr *)(((char *)embedded_udp) +
                sizeof(struct ip6_frag));
    }

    if ( next_header != IPPROTO_UDP ) {
        return;
    }

    /* check the packet has the index/indent values we set when we sent it */
    ipv6_body = (struct ipv6_body_t *)(embedded_udp + 1);
    index = ntohs(ipv6_body->index);
    ttl = index >> 10;
    index &= 0x3FF;

    if ( ident != ntohs(ipv6_body->ident) ) {
        return;
    }

    if ( index < 0 || index > count ) {
        return;
    }

    /* record the delay between sending this probe and getting a response */
    if ( info[index].hop[ttl - 1].delay == 0 ) {
        info[index].hop[ttl - 1].delay =
            DIFF_TV_US(now, info[index].hop[ttl - 1].time_sent);
    }

    /* if it's not an error we are expecting, record it and return */
    if ( icmp6->icmp6_type != ICMP6_TIME_EXCEEDED &&
            (icmp6->icmp6_type == ICMP6_DST_UNREACH &&
            icmp6->icmp6_code != ICMP6_DST_UNREACH_NOPORT) ) {
        info[index].err_type = icmp6->icmp6_type;
        info[index].err_code = icmp6->icmp6_code;
        return;
    }

    /* record the address that replied to our probe */
    if ( HOP_REPLY(index, ttl) ) {
        Log(LOG_DEBUG, "Duplicate reply for hop %d from %s\n",
                info[index].ttl - 1, "XXX");
    } else {
        HOP_REPLY(index, ttl) = 1;
        HOP_ADDR(index, ttl) =
            (struct addrinfo *)malloc(sizeof(struct addrinfo));
        HOP_ADDR(index, ttl)->ai_addr =
            (struct sockaddr *)malloc(sizeof(struct sockaddr_in6));
        HOP_ADDR(index, ttl)->ai_family = AF_INET6;
        HOP_ADDR(index, ttl)->ai_addrlen = sizeof(struct sockaddr_in6);
        memcpy(&((struct sockaddr_in6 *)HOP_ADDR(index, ttl)->ai_addr)->sin6_addr, addr->sin6_addr.s6_addr, sizeof(struct in6_addr));
        HOP_ADDR(index, ttl)->ai_canonname = NULL;
        HOP_ADDR(index, ttl)->ai_next = NULL;
    }

    /* port unreachable means we have reached the destination */
    if ( icmp6->icmp6_type == ICMP6_DST_UNREACH &&
            icmp6->icmp6_code == ICMP6_DST_UNREACH_NOPORT ) {
        if ( info[index].ttl == TRACEROUTE_FULL_PATH_PROBE_TTL ) {
            info[index].ttl = MAX_HOPS_IN_PATH -
                embedded_ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim + 1;
        }
        info[index].done = 1;
        return;
    }

    if ( info[index].ttl >= MAX_HOPS_IN_PATH ) {
        info[index].done = 1;
    } else {
        /*
         * Only reset these counters if the response was on time, otherwise
         * we have already moved on and they are no longer related to this
         * hop. The only reason we have got this far was to record the address
         * and latency rather than ignoring this response packet entirely and
         * leaving a gap that could have been avoided.
         */
        if ( info[index].hop[ttl - 1].delay < LOSS_TIMEOUT ) {
            info[index].ttl++;
            info[index].attempts = 0;
            info[index].no_reply_count = 0;
        }
    }

}



/*
 *
 */
static void harvest(struct socket_t *icmp_sockets, uint16_t ident, int wait,
        int count, struct info_t *info) {

    struct sockaddr_storage addr;
    char packet[2048]; //XXX what is a sensible maximum size?
    struct timeval now;

    /*
     * Read packets until we hit the timeout. Note that wait is reduced by
     * the call to get_packet()
     */
    while ( get_packet(icmp_sockets, packet, 1024, (struct sockaddr *)&addr,
                &wait) ) {

	gettimeofday(&now, NULL);
        switch ( ((struct iphdr*)packet)->version ) {
            case 4: process_ipv4_packet(packet, now, ident, count, info);
		    break;
	    default: /* we don't have an ipv6 header here */
		    process_ipv6_packet(packet, (struct sockaddr_in6 *)&addr,
                            now, ident, count, info);
		    break;
	};
    }
}



/*
 *
 */
static int inc_attempt_counter(struct info_t *info) {
    /* Try again if we haven't done too many yet */
    if ( ++(info->attempts) <= TRACEROUTE_RETRY_LIMIT ) {
        return 1;
    }

    /* Too many attempts at this hop, mark is as no reply */
    info->hop[info->ttl - 1].addr = NULL;
    info->no_reply_count++;

    /* Check if we haven't missed too many responses in the path */
    if ( info->path_length == 0 &&
            info->no_reply_count >= TRACEROUTE_NO_REPLY_LIMIT ) {
        /* Give up, too many missing replies */
        info->done = 1;
        return 0;
    }

    /* Check if we haven't already tried too many hops */
    if ( info->ttl >= MAX_HOPS_IN_PATH ||
            (info->path_length > 0 && info->ttl > info->path_length) ) {
        /* Path is too long, stop here */
        info->done = 1;
        return 0;
    }

    /* Try the next hop */
    info->ttl++;
    info->attempts = 1;
    return 1;
}



/*
 * Send a high-TTL probe to try to get a response from the target, establishing
 * the maximum path length that should be probed. If there is no response then
 * the traceroute test will continue until the destination does respond, or
 * 5 consecutive hops fail to respond.
 */
#if 0
static uint8_t get_path_length(struct socket_t *icmp_sockets,
        struct socket_t *ip_sockets, uint16_t ident,
        struct addrinfo *dest, struct opt_t *opt) {

    struct info_t info;
    int i;

    /*
     * Change the ident value so we don't later confuse these packets
     * with our test traffic
     */
    ident = ident + 1;

    memset(&info, 0, sizeof(info));
    info.addr = dest;
    info.ttl = TRACEROUTE_FULL_PATH_PROBE_TTL;

    send_probe(ip_sockets, 0, MAX_HOPS_IN_PATH, ident, dest, &info, opt);
    harvest(icmp_sockets, ident, 1000000, 1, &info);

    /* Free any response data */
    for ( i = 0; i < MAX_HOPS_IN_PATH; i++ ) {
        if ( info.hop[i].reply ) {
            /* we've allocated ai_addr ourselves, so have to free it */
            free(info.hop[i].addr->ai_addr);
            freeaddrinfo(info.hop[i].addr);
        }
    }

    if ( info.done && info.err_type == 0 ) {
        return info.ttl;
    }
    return 0;
}
#endif



/*
 * Open the raw ICMP and ICMPv6 sockets used for this test and configure
 * appropriate filters for the ICMPv6 socket.
 */
static int open_sockets(struct socket_t *icmp_sockets,
        struct socket_t *ip_sockets) {

    int header = 1;
    struct icmp6_filter filter;

    /* Open IPv4 raw socket for ICMP responses */
    if ( (icmp_sockets->socket =
		socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMP");
    } else {
        /* Open IPv4 RAW socket for sending probes */
        if ( (ip_sockets->socket =
                    socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 ) {
            Log(LOG_WARNING, "Failed to open raw socket for IP");
            close(icmp_sockets->socket);
            icmp_sockets->socket = -1;
        } else {
            /* Set socket options to include our own IP header in raw packets */
            if ( setsockopt(ip_sockets->socket, IPPROTO_IP, IP_HDRINCL,
                        &header, sizeof(header)) < 0 ) {
                Log(LOG_WARNING,
                        "Failed to set header included option on raw socket");
                close(icmp_sockets->socket);
                close(ip_sockets->socket);
                icmp_sockets->socket = -1;
            }
        }
    }

    /* Open IPv6 raw socket for ICMP responses */
    if ( (icmp_sockets->socket6 =
		socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMPV6");
    } else {
        /* Open IPv6 UDP socket for sending probes */
        if ( (ip_sockets->socket6 =
                    socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
            Log(LOG_WARNING, "Failed to open IPv6 UDP socket");
            close(icmp_sockets->socket6);
            icmp_sockets->socket6 = -1;
        } else {
            /* Set IPv6 filter to only pass destination unreachable and TTL
             * expired messages
             */
            ICMP6_FILTER_SETBLOCKALL(&filter);
            ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
            ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filter);
            if ( setsockopt(icmp_sockets->socket6, SOL_ICMPV6, ICMP6_FILTER,
                        &filter, sizeof(struct icmp6_filter)) < 0 ) {
                Log(LOG_WARNING, "Failed to set ICMPV6 filters");
                close(icmp_sockets->socket6);
                close(ip_sockets->socket6);
                icmp_sockets->socket6 = -1;
            }
        }
    }

    /* make sure at least one type of socket was opened */
    if ( icmp_sockets->socket < 0 && icmp_sockets->socket6 < 0 ) {
	return 0;
    }

    return 1;
}


/* XXX TODO library function, lots of tests will use this */
static void extract_address(void *dst, const struct addrinfo *src) {
    assert(src);
    assert(dst);

    switch ( src->ai_family ) {
        case AF_INET:
            memcpy(dst, &((struct sockaddr_in*) src->ai_addr)->sin_addr,
                    sizeof(struct in_addr));
            break;
        case AF_INET6:
            memcpy(dst, &((struct sockaddr_in6*) src->ai_addr)->sin6_addr,
                    sizeof(struct in6_addr));
            break;
        default:
            Log(LOG_WARNING, "Unknown address family %d\n", src->ai_family);
            memset(dst, 0, 16);//XXX
            break;
    };
}



/*
 *
 */
static void report_results(struct timeval *start_time, int count,
	struct info_t info[], struct opt_t *opt) {
    int i;
    int hopcount;
    char *buffer;
    struct traceroute_report_header_t *header;
    struct traceroute_report_path_t *path;
    struct traceroute_report_hop_t *hop;
    int len;
    char addrstr[INET6_ADDRSTRLEN];
    int reported_hops = 0;

    Log(LOG_DEBUG, "Building traceroute report, count:%d, psize:%d, rand:%d\n",
	    count, opt->packet_size, opt->random);

    /* allocate space for our header and paths XXX could this get too large? */
    len = sizeof(struct traceroute_report_header_t) +
	count * sizeof(struct traceroute_report_path_t);
    buffer = malloc(len);
    memset(buffer, 0, len);

    /* single header at the start of the buffer describes the test options */
    header = (struct traceroute_report_header_t *)buffer;
    header->version = AMP_TRACEROUTE_TEST_VERSION;
    header->packet_size = opt->packet_size;
    header->random = opt->random;
    header->count = count;

    /* add results for all the destinations */
    for ( i = 0; i < count; i++ ) {

        /* add in space for the hops on this path  */
        len += info[i].ttl * sizeof(struct traceroute_report_hop_t);
        buffer = realloc(buffer, len);

        /* global information regarding this particular path */
	path = (struct traceroute_report_path_t *)(buffer +
		sizeof(struct traceroute_report_header_t) +
		i * sizeof(struct traceroute_report_path_t) +
                reported_hops * sizeof(struct traceroute_report_hop_t));

	strncpy(path->name, address_to_name(info[i].addr),
		sizeof(path->name));
	path->family = info[i].addr->ai_family;
	path->length = info[i].ttl;
        path->err_code = info[i].err_code;
        path->err_type = info[i].err_type;
        extract_address(&path->address, info[i].addr);

        inet_ntop(path->family, path->address, addrstr, INET6_ADDRSTRLEN);
	Log(LOG_DEBUG, "path result %d: %d hops to %s\n", i, path->length,
		addrstr);

        /* per-hop information for this path */
        for ( hopcount = 0; hopcount < path->length; hopcount++ ) {
            hop = (struct traceroute_report_hop_t *)(((char *)path) +
                    sizeof(struct traceroute_report_path_t) +
                    (hopcount * sizeof(struct traceroute_report_hop_t)));

            if ( info[i].hop[hopcount].addr == NULL ) {
                memset(hop->address, 0, sizeof(hop->address));
                hop->rtt = -1;
            } else {
                extract_address(hop->address, info[i].hop[hopcount].addr);
                hop->rtt = info[i].hop[hopcount].delay;
            }
            inet_ntop(path->family, hop->address, addrstr, INET6_ADDRSTRLEN);
            reported_hops++;
            Log(LOG_DEBUG, " %d: %s %d\n", hopcount+1, addrstr, hop->rtt);
        }
    }

    report(AMP_TEST_TRACEROUTE,
            (uint64_t)start_time->tv_sec, (void*)buffer, len);
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
 * Reimplementation of the traceroute test from AMP
 *
 * TODO get useful errors into the log strings
 * TODO get test name into log strings
 * TODO logging will need more work - the log level won't be set.
 * TODO const up the dest arguments so cant be changed?
 */
int run_traceroute(int argc, char *argv[], int count, struct addrinfo **dests) {
    int opt;
    struct opt_t options;
    struct timeval start_time, now;
    struct socket_t icmp_sockets, ip_sockets;
    struct info_t *info;
    int i;
    int hop;
    int work;
    int send;
    int min_wait;
    int delay;
    uint16_t ident;

    Log(LOG_DEBUG, "Starting TRACEROUTE test");

    /* set some sensible defaults */
    options.packet_size = DEFAULT_TRACEROUTE_PROBE_LEN;
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
	options.packet_size = MIN_TRACEROUTE_PROBE_LEN +
            (int)((1500 - MIN_TRACEROUTE_PROBE_LEN)
                    * (random()/(RAND_MAX+1.0)));
	Log(LOG_DEBUG, "Setting packetsize to random value: %d\n",
		options.packet_size);
    }

    /* make sure that the packet size is big enough for our data */
    if ( options.packet_size < MIN_TRACEROUTE_PROBE_LEN ) {
	Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
		options.packet_size, MIN_TRACEROUTE_PROBE_LEN);
	options.packet_size = MIN_TRACEROUTE_PROBE_LEN;
    }

    /* delay the start by a random amount of perturbate is set */
    if ( options.perturbate ) {
	int delay;
	delay = options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		options.perturbate, delay);
	usleep(delay);
    }

    if ( !open_sockets(&icmp_sockets, &ip_sockets) ) {
	Log(LOG_ERR, "Unable to open sockets, aborting test");
	exit(-1);
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(-1);
    }

    /*
     * Use part of the current time as an identifier value. This gets used
     * as the source port for ipv4 tests and the ident value in ipv6.
     */
    ident = (uint16_t)start_time.tv_usec;
    if ( ident < 9000 ) {
        /* bump it above the port range used for normal AMP tests */
        ident += 9000;
    }

    /* allocate space to store information about each request sent */
    info = (struct info_t *)malloc(sizeof(struct info_t) * count);
    memset(info, 0, sizeof(struct info_t) * count);

    /* set destinations and initialise path information */
    for ( i=0; i<count; i++ ) {
#if 0
        /* try to establish the length of the path so that we don't send
         * too many probes, or probe the end host multiple times if it is
         * slow to respond.
         */
        info[i].path_length = get_path_length(&icmp_sockets, &ip_sockets,
                ident, dests[i], &options);
        if ( info[i].path_length <= 2 ) {
            Log(LOG_DEBUG, "Path length is too short (%d), ignoring\n",
                    info[i].path_length);
            info[i].path_length = 0;
        }
#endif
        info[i].addr = dests[i];
        info[i].ttl = 1;
    }

    work = 1;
    while ( work ) {
        work = 0;
        min_wait = LOSS_TIMEOUT;
        gettimeofday(&now, NULL);

        for ( i=0; i<count; i++ ) {
            if ( info[i].done ) {
                continue;
            }
            work = 1;
            send = 0;

            if ( info[i].attempts == 0 || info[i].retry ) {
                /* first attempt or a retry is forced, send a probe now */
                send = 1;
            } else if ( (delay=DIFF_TV_US(now, info[i].last_time_sent)) <
                    LOSS_TIMEOUT ) {
                /* still waiting for an outstanding probe */
                if ( delay < min_wait ) {
                    min_wait = delay;
                }
            } else {
                /* this try has timed out, try again */
                send = 1;
            }

            if ( send ) {
                /*
                 * Make sure that we should be sending this packet (haven't
                 * had too many attempts, too many non-responsive hops, etc).
                 */
                if ( inc_attempt_counter(&(info[i])) ) {
                    info[i].last_time_sent.tv_sec = now.tv_sec;
                    info[i].last_time_sent.tv_usec = now.tv_usec;
                    send_probe(&ip_sockets, i, info[i].ttl, ident, dests[i],
                            info, &options);
                    harvest(&icmp_sockets, ident, MIN_INTER_PACKET_DELAY,
                            count, info);
                    min_wait = 0;
                }
            }
        }

        if ( work && wait_for_data(&icmp_sockets, &min_wait) ) {
            harvest(&icmp_sockets, ident, 0, count, info);
        }
    }

    /* sockets aren't needed any longer */
    if ( icmp_sockets.socket > 0 ) {
	close(icmp_sockets.socket);
	close(ip_sockets.socket);
    }

    if ( icmp_sockets.socket6 > 0 ) {
	close(icmp_sockets.socket6);
	close(ip_sockets.socket6);
    }

    /* send report */
    report_results(&start_time, count, info, &options);

    /* tidy up */
    for ( i = 0; i < count; i++ ) {
        for ( hop = 0; hop < MAX_HOPS_IN_PATH; hop++ ) {
            if ( info[i].hop[hop].reply ) {
                /* we've allocated ai_addr ourselves, so have to free it */
                free(info[i].hop[hop].addr->ai_addr);
                freeaddrinfo(info[i].hop[hop].addr);
            }
        }
    }
    free(info);

    return 0;
}



/*
 * Print trace test results to stdout, nicely formatted for the standalone test
 */
void print_traceroute(void *data, uint32_t len) {
    struct traceroute_report_header_t *header =
        (struct traceroute_report_header_t*)data;
    struct traceroute_report_path_t *path;
    struct traceroute_report_hop_t *hop;
    char addrstr[INET6_ADDRSTRLEN];
    int i;
    int hopcount;
    int reported_hops = 0;

    assert(data != NULL);
    assert(len >= sizeof(struct traceroute_report_header_t));
    assert(header->version == AMP_TRACEROUTE_TEST_VERSION);

    printf("\n");
    printf("AMP traceroute test, %u destinations, %u byte packets ",
            header->count, header->packet_size);
    if ( header->random ) {
	printf("(random size)\n");
    } else {
	printf("(fixed size)\n");
    }

    for ( i=0; i<header->count; i++ ) {
        /* specific path information */
	path = (struct traceroute_report_path_t*)(data +
		sizeof(struct traceroute_report_header_t) +
		i * sizeof(struct traceroute_report_path_t) +
                reported_hops * sizeof(struct traceroute_report_hop_t));
        printf("\n");
	printf("%s", path->name);
	inet_ntop(path->family, path->address, addrstr, INET6_ADDRSTRLEN);
	printf(" (%s)\n", addrstr);

        /* per-hop information for this path */
        for ( hopcount = 0; hopcount < path->length; hopcount++ ) {
           hop = (struct traceroute_report_hop_t *)(((char *)path) +
                   sizeof(struct traceroute_report_path_t) +
                   (hopcount * sizeof(struct traceroute_report_hop_t)));
           inet_ntop(path->family, hop->address, addrstr, INET6_ADDRSTRLEN);
           printf(" %.2d  %s %dus", hopcount+1, addrstr, hop->rtt);
           if ( path->err_type > 0 ) {
                printf(" error: %d/%d", path->err_type, path->err_code);
           }
           printf("\n");
           reported_hops++;
        }
    }
    printf("\n");

}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_TRACEROUTE;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("traceroute");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 180;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_traceroute;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_traceroute;

    return new_test;
}
