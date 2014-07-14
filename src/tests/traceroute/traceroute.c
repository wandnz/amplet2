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
#include "config.h"
#include "testlib.h"
#include "traceroute.h"
#include "libwandevent.h"


int total_packets = 0;


static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"interface", required_argument, 0, 'I'},
    {"perturbate", required_argument, 0, 'p'},
    {"random", no_argument, 0, 'r'},
    {"size", required_argument, 0, 's'},
    {"version", no_argument, 0, 'v'},
    {"ipv4", required_argument, 0, '4'},
    {"ipv6", required_argument, 0, '6'},
    {NULL, 0, 0, 0}
};


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
static int send_probe(struct socket_t *ip_sockets, uint16_t ident,
        struct dest_info_t *info) {

    char packet[60];//XXX
    long int delay;
    uint16_t id;
    int sock;
    int length;

    assert(ip_sockets);
    assert(info);

    memset(packet, 0, sizeof(packet));
    id = (info->ttl << 10) + info->id;

    switch ( info->addr->ai_family ) {
        case AF_INET: {
            //printf("sending probe over ipv4\n");
            sock = ip_sockets->socket;
            length = build_ipv4_probe(packet, 60/*opt->packet_size*/, id,
                    info->ttl, ident, info->addr);
        } break;

        case AF_INET6: {
            int ttl = info->ttl;
            //printf("sending probe over ipv6\n");
            sock = ip_sockets->socket6;
            //if ( setsockopt(sock, SOL_IPV6, IPV6_UNICAST_HOPS, &info->ttl,
            //        sizeof(info->ttl)) < 0 ) {
            if ( setsockopt(sock, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl,
                    sizeof(ttl)) < 0 ) {
                printf("failed to set ttl to %d\n", info->ttl);
                printf("error setting IPV6_UNICAST_HOPS: %s\n",
                        strerror(errno));
            }
            length = build_ipv6_probe(packet, 60/*opt->packet_size*/, id,
                    ident, info->addr);
        } break;

        default:
	    Log(LOG_WARNING, "Unknown address family: %d",
                    info->addr->ai_family);
	    return -1;
    };
    //printf("sending probe with ttl %d\n", info->ttl);

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, packet, length, info->addr)) > 0 ){
        printf("BAD: sleeping for %ldus cause we triggered too early\n", delay);
        usleep(delay);
    }

    total_packets++;
    info->probes++;
    printf("send probe %d/%d attempt %d\n", info->id, info->ttl, info->attempts);

    if ( delay < 0 ) {
        int i;
        info->done_forward = 1;
        info->done_backward = 1;
        info->ttl = 5;
        for ( i = 0; i < info->ttl; i++ ) {
            info->hop[i].addr = NULL;
        }
        return -1;
    } else {
        gettimeofday(&(info->hop[info->ttl - 1].time_sent), NULL);
        /*
        printf("probe %d to destination %d should expire at %d.%06d\n",
                info->ttl, info->id,
                info->hop[info->ttl - 1].time_sent.tv_sec + 5,
                info->hop[info->ttl - 1].time_sent.tv_usec);
        */
    }

    return 0;
}

/*
 * Extract the index value that has been encoded into the IP ID field.
 */
static int get_index(int family, char *embedded,
        struct probe_list_t *probelist) {

    uint16_t index, ident;

    switch ( family ) {
        case AF_INET: {
                /* ipv4 stores the index in the ip id field of the probe */
                struct iphdr *ip = (struct iphdr*)embedded;
                struct udphdr *udp;

                /* make sure the embedded packet is UDP */
                if ( ip->protocol != IPPROTO_UDP ) {
                    return -1;
                }

                /* ipv4 probes use the udp source port as the ident value */
                udp = (struct udphdr *)(((char *)ip) + (ip->ihl << 2));
                index = ntohs(ip->id);
                ident = ntohs(udp->source);
            }
            break;

        case AF_INET6: {
                /* ipv6 stores the index in the body of the probe */
                struct ip6_hdr *ipv6 = (struct ip6_hdr *)embedded;
                struct udphdr *udp = (struct udphdr *)(ipv6 + 1);
                int next_header = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
                struct ipv6_body_t *ipv6_body;

                /* jump to start of the fragment if there is a frag header */
                if ( next_header == IPPROTO_FRAGMENT ) {
                    /*
                     * The first field in the fragment header (where udp
                     * currently points) is the next header field for what the
                     * fragment contains. The fragment itself starts directly
                     * after the 8 byte fragment header.
                     */
                    next_header = *(uint8_t*)udp;
                    udp = (struct udphdr *)(((char *)udp) +
                            sizeof(struct ip6_frag));
                }

                if ( next_header != IPPROTO_UDP ) {
                    return -1;
                }

                /* ipv6 probes store the ident in the body also */
                ipv6_body = (struct ipv6_body_t *)(udp + 1);
                index = ntohs(ipv6_body->index);
                ident = ntohs(ipv6_body->ident);
            }
            break;

        default: return -1;
    };

    if ( ident != probelist->ident ) {
        return -1;
    }

    //printf("index %d vs count %d\n", index, probelist->count);

    if ( (index & 0x3FF) >= probelist->count ) {
        /*
         * According to the original traceroute test:
         * some boxes are broken and byteswap the ip id field but
         * don't put it back before putting it into the end of the
         * icmp error. Check if swapping the byte order makes the
         * ip id match what we were expecting...
         */
        if ( (ntohs(index) & 0x3FF) < probelist->count ) {
            return ntohs(index);
        }
        Log(LOG_DEBUG, "Bad index %d in embedded packet ignored", index&0x3FF);
        return -1;
    }

    return index;
}



/*
 * XXX this modifies item
 */
static int inc_probe_ttl(struct dest_info_t *item) {
    if ( item->attempts > TRACEROUTE_RETRY_LIMIT && !item->first_response ) {
        /* the very first probe has timed out without a response */
        item->ttl = item->ttl / 2;
        item->no_reply_count = 0;
    } else if ( !item->done_forward ) {
        /* timeout while probing forward, skip to the next unprobed ttl */
        item->ttl++;
        while ( item->hop[item->ttl - 1].reply == REPLY_TIMED_OUT ) {
            item->no_reply_count++;
            item->ttl++;
        }
    } else {
        /* timeout while probing backwards, decrement ttl towards zero */
        item->ttl--;
    }

    /* new ttl value, reset the attempt counter */
    item->attempts = 0;

    return item->ttl;
}



/*
 *
 */
static int inc_attempt_counter(struct dest_info_t *info) {
    /* Try again if we haven't done too many yet */
    if ( ++(info->attempts) <= TRACEROUTE_RETRY_LIMIT ) {
        return 1;
    }

    /* Too many attempts at this hop, mark is as no reply */
    info->hop[info->ttl - 1].addr = NULL;
    info->hop[info->ttl - 1].reply = REPLY_TIMED_OUT;
    info->no_reply_count++;//XXX only do this on forward probes?

    if ( !info->done_forward &&
            (info->no_reply_count >= TRACEROUTE_NO_REPLY_LIMIT ||
            info->ttl >= MAX_HOPS_IN_PATH) ) {
        /* Give up, hit a limit going forward, try probing backwards now */
        info->done_forward = 1;
        info->path_length = info->ttl;
        info->ttl = info->first_response - 1;
        info->attempts = 0;
        info->no_reply_count = 0;
        return info->ttl;
    }

    return inc_probe_ttl(info);
}



/* find the item that triggered this probe in the outstanding list */
static struct dest_info_t *find_outstanding_item(struct probe_list_t *probelist,
        int index, int ttl) {

    struct dest_info_t *prev, *item;

    for ( prev = NULL, item = probelist->outstanding;
            item != NULL; prev = item, item = item->next ) {

        if ( item->id == index && item->ttl == ttl ) {
            if ( prev == NULL ) {
                probelist->outstanding = item->next;
                if ( probelist->outstanding == NULL ) {
                    probelist->outstanding_end = NULL;
                }
            } else {
                prev->next = item->next;
                if ( prev->next == NULL ) {
                    probelist->outstanding_end = prev;
                }
            }
            item->next = NULL;
            break;
        }
    }

    return item;
}


static int unexpected_error(int family, int type) {

    switch ( family ) {
        case AF_INET:
            if ( type != ICMP_TIME_EXCEEDED && type != ICMP_DEST_UNREACH ) {
                return 1;
            }
            break;

        case AF_INET6:
            if ( type != ICMP6_TIME_EXCEEDED && type != ICMP6_DST_UNREACH ) {
                return 1;
            }
            break;

        default: break;
    };

    return 0;
}



static int terminal_error(int family, int type) {

    switch ( family ) {
        case AF_INET:
            if ( type != ICMP_PARAMETERPROB && type != ICMP_DEST_UNREACH ) {
                return 0;
            }
            break;

        case AF_INET6:
            if ( type != ICMP6_PARAM_PROB && type != ICMP6_DST_UNREACH ) {
                return 0;
            }
            break;

        default: break;
    };

    return 1;
}


static int append_ready_item(struct probe_list_t *probelist,
        struct dest_info_t *item) {

    assert(probelist);
    assert(item);

    if ( probelist->ready == NULL ) {
        probelist->ready = item;
        probelist->ready_end = item;
        return 1;
    }

    probelist->ready_end->next = item;
    probelist->ready_end = item;

    return 0;
}


static char *get_embedded_ipv4_packet(char *packet) {
    struct iphdr *ip;
    struct iphdr *embedded_ip;
    struct icmphdr *icmp;

    assert(packet);

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
        return NULL;
    }

    /* make sure that what we have embedded is one of our UDP probes */
    embedded_ip = (struct iphdr *)(((char *)icmp) + sizeof(struct icmphdr));
    if ( embedded_ip->protocol != IPPROTO_UDP ) {
        return NULL;
    }

    return (char*)embedded_ip;
}


static char *get_embedded_ipv6_packet(char *packet) {
    struct icmp6_hdr *icmp6;

    /* we get an ICMPv6 header here, the IP header has been stripped already */
    icmp6 = (struct icmp6_hdr *)packet;

    /*
     * Make sure the response is of the right type, others can slip through
     * while the filter is being established.
     */
    if ( icmp6->icmp6_type != ICMP6_DST_UNREACH &&
            icmp6->icmp6_type != ICMP6_TIME_EXCEEDED ) {
        return NULL;
    }

    /* the response is the right type so we should have an embedded packet */
    return (char*)((struct ip6_hdr *)(icmp6 + 1));
}



static char *get_embedded_packet(int family, char *packet) {
    switch ( family ) {
        case AF_INET: return get_embedded_ipv4_packet(packet); break;
        case AF_INET6: return get_embedded_ipv6_packet(packet); break;
        default: return NULL;
    };
}



static int get_icmp_code(int family, char *packet) {
    switch ( family ) {
        case AF_INET: {
                struct iphdr *ip = (struct iphdr *)packet;
                struct icmphdr *icmp = (struct icmphdr*)(packet+(ip->ihl << 2));
                return icmp->code;
            }
            break;

        case AF_INET6: {
               struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet;
               return icmp6->icmp6_code;
            }
            break;

        default: return -1;
    };
}


static int get_icmp_type(int family, char *packet) {
    switch ( family ) {
        case AF_INET: {
                struct iphdr *ip = (struct iphdr *)packet;
                struct icmphdr *icmp = (struct icmphdr*)(packet+(ip->ihl << 2));
                return icmp->type;
            }
            break;

        case AF_INET6: {
               struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet;
               return icmp6->icmp6_type;
            }
            break;

        default: return -1;
    };
}



static int get_embedded_ttl(int family, char *packet) {
    char *embedded;

    if ( (embedded = get_embedded_packet(family, packet)) == NULL ) {
        return -1;
    }

    switch ( family ) {
        case AF_INET:
            return ((struct iphdr *)embedded)->ttl;
        case AF_INET6:
            return ((struct ip6_hdr*)embedded)->ip6_ctlun.ip6_un1.ip6_un1_hlim;
        default:
            return -1;
    };
}


/*
 *
 */
static int process_packet(int family, struct sockaddr *addr, char *packet,
        struct timeval now, struct probe_list_t *probelist ) {

    struct dest_info_t *item;
    int ttl, index, type, code;
    char *embedded;

    /* XXX rule out stupid responses */

    //printf("process_packet()\n");

    /* get the embedded packet if there is a valid one present */
    if ( (embedded = get_embedded_packet(family, packet)) == NULL ) {
        return -1;
    }

    /* check that the index and ident are valid */
    if ( (index = get_index(family, embedded, probelist)) < 0 ) {
        return -1;
    }

    ttl = index >> 10;
    index &= 0x3FF;
    type = get_icmp_type(family, packet);
    code = get_icmp_code(family, packet);

    //printf("response %d/%d for destination %d/%d\n", type, code, index, ttl);

    /* Find the item this response refers to */
    if ( (item = find_outstanding_item(probelist, index, ttl)) == NULL ) {
        return -1;
    }

    /* we've hit the destination on the first go so need the real ttl */
    if ( terminal_error(family, type) && item->ttl == INITIAL_TTL ) {
        if ( (ttl = get_embedded_ttl(family, packet)) < 0 ) {
            item->done_forward = 1;
            item->done_backward = 1;
            item->next = probelist->done;
            probelist->done = item;
            return -1;
        }

        /* determine path length based on remaining TTL in embedded packet */
        item->ttl = ttl = INITIAL_TTL - ttl;

        /* TTL of 1 means 1 ipv4 hop away, TTL of 0 means 1 ipv6 hop away */
        if ( item->ttl > 1 || item->ttl == 0 ) {
            item->ttl++;
            ttl++;
        }

        /* take the time the original probe to INITIAL_TTL was sent */
        item->hop[ttl - 1].time_sent = item->hop[INITIAL_TTL - 1].time_sent;
        printf("hit destination on first probe, actual ttl %d\n", item->ttl);
    }

    /* record the delay between sending this probe and getting a response */
    if ( item->hop[ttl - 1].delay == 0 ) {
        item->hop[ttl - 1].delay =
            DIFF_TV_US(now, item->hop[ttl - 1].time_sent);
    }

    /* if unexpected error, record it and look to keep probing */
    if ( unexpected_error(family, type) ) {
        item->err_type = type;
        item->err_code = code;

        /* reschedule if this is an error we can recover from */
        if ( !terminal_error(family, type) && inc_attempt_counter(item) ) {
            return append_ready_item(probelist, item);
        }

        /* otherwise end probing here */
        //XXX can we still probe backwards?
        item->done_forward = 1;
        item->next = probelist->done;
        probelist->done = item;
        return 0;
    }

    /* XXX no longer checking if port unreachables are from correct source */
    printf("accepted response for hop %d\n", ttl);
    if ( !item->first_response ) {
        item->first_response = ttl;
    }

    /* if expected error, update hop information */
    HOP_REPLY(ttl) = REPLY_OK;
    HOP_ADDR(ttl) = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    switch ( family ) {
        case AF_INET:
            HOP_ADDR(ttl)->ai_addr =
                (struct sockaddr *)malloc(sizeof(struct sockaddr_in));
            HOP_ADDR(ttl)->ai_addrlen = sizeof(struct sockaddr_in);
            memcpy(&((struct sockaddr_in *)HOP_ADDR(ttl)->ai_addr)->sin_addr,
                    &((struct sockaddr_in*)addr)->sin_addr.s_addr,
                    sizeof(struct in_addr));
            break;

        case AF_INET6:
            HOP_ADDR(ttl)->ai_addr =
                (struct sockaddr *)malloc(sizeof(struct sockaddr_in6));
            HOP_ADDR(ttl)->ai_addrlen = sizeof(struct sockaddr_in6);
            memcpy(&((struct sockaddr_in6 *)HOP_ADDR(ttl)->ai_addr)->sin6_addr,
                    &((struct sockaddr_in6*)addr)->sin6_addr.s6_addr,
                    sizeof(struct in6_addr));
            break;
    };
    HOP_ADDR(ttl)->ai_family = family;
    HOP_ADDR(ttl)->ai_canonname = NULL;
    HOP_ADDR(ttl)->ai_next = NULL;

    /* XXX end probing if going backwards and reached a known point */
    if ( item->done_forward && item->ttl == 1 ) {
        item->done_backward = 1;
        item->next = probelist->done;
        probelist->done = item;
        return 0;
    }

    /*
     * End forward probing and begin backwards probing if this is a terminal
     * error or if the path is too long.
     */
    if ( terminal_error(family, type) || item->ttl >= MAX_HOPS_IN_PATH ) {
        item->done_forward = 1;
        item->path_length = item->ttl;
        item->ttl = item->first_response - 1;
        if ( item->ttl == 0 ) {
            item->done_backward = 1;
            item->next = probelist->done;
            probelist->done = item;
            return 0;
        }
        item->attempts = 0;
        item->no_reply_count = 0;
        return append_ready_item(probelist, item);
    }

    /*
     * Only reset these counters if the response was on time, otherwise
     * we have already moved on and they are no longer related to this
     * hop. The only reason we have got this far was to record the address
     * and latency rather than ignoring this response packet entirely and
     * leaving a gap that could have been avoided.
     */
    if ( item->hop[ttl - 1].delay < LOSS_TIMEOUT ) {
        item->no_reply_count = 0;
        item->attempts = 0;
        if ( inc_probe_ttl(item) < 1 ) {
            item->done_backward = 1;
            item->next = probelist->done;
            probelist->done = item;
            return 0;
        }
        return append_ready_item(probelist, item);
    }

    return 0;
}



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
    memset(dst, 0, sizeof(struct in6_addr));

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
            break;
    };
}



/*
 *
 */
static void report_results(struct timeval *start_time, int count,
	struct dest_info_t* info, struct opt_t *opt) {
    int hopcount;
    char *buffer;
    struct traceroute_report_header_t *header;
    struct traceroute_report_path_t *path;
    struct traceroute_report_hop_t *hop;
    int len;
    char addrstr[INET6_ADDRSTRLEN];
    int offset;
    struct dest_info_t *item;

    Log(LOG_DEBUG, "Building traceroute report, count:%d, psize:%d, rand:%d\n",
	    count, opt->packet_size, opt->random);

    /* allocate space for our header */
    len = sizeof(struct traceroute_report_header_t);
    buffer = malloc(len);
    memset(buffer, 0, len);

    /* single header at the start of the buffer describes the test options */
    header = (struct traceroute_report_header_t *)buffer;
    header->version = htonl(AMP_TRACEROUTE_TEST_VERSION);
    header->packet_size = htons(opt->packet_size);
    header->random = opt->random;
    header->count = count;

    offset = sizeof(struct traceroute_report_header_t);

    /* add results for all the destinations */
    //for ( i = 0; i < count; i++ ) {
    for ( item = info; item != NULL; item = item->next ) {
        char *ampname = address_to_name(item->addr);
        assert(ampname);
        assert(strlen(ampname) < MAX_STRING_FIELD);

        /* add in space for the path header and its hops */
        len += (sizeof(struct traceroute_report_path_t)) +
            (item->path_length * sizeof(struct traceroute_report_hop_t)) +
            (strlen(ampname) + 1);
        buffer = realloc(buffer, len);

        /* global information regarding this particular path */
        path = (struct traceroute_report_path_t *)(buffer + offset);
        offset += sizeof(struct traceroute_report_path_t);

	path->family = item->addr->ai_family;
	path->length = item->path_length;
        path->err_code = item->err_code;
        path->err_type = item->err_type;
        extract_address(&path->address, item->addr);

        /* add variable length ampname onto the buffer, after the path item */
        path->namelen = strlen(ampname) + 1;
        strncpy(buffer + offset, ampname, path->namelen);
        offset += path->namelen;

        inet_ntop(path->family, path->address, addrstr, INET6_ADDRSTRLEN);
	Log(LOG_DEBUG, "path result %d: %d hops to %s\n", item->id,
                path->length, addrstr);

        /* per-hop information for this path */
        for ( hopcount = 0; hopcount < path->length; hopcount++ ) {
            hop = (struct traceroute_report_hop_t *)(buffer + offset);
            offset += sizeof(struct traceroute_report_hop_t);

            if ( item->hop[hopcount].addr == NULL ) {
                memset(hop->address, 0, sizeof(hop->address));
                hop->rtt = htonl(-1);
            } else {
                extract_address(hop->address, item->hop[hopcount].addr);
                hop->rtt = htonl(item->hop[hopcount].delay);
            }
            inet_ntop(path->family, hop->address, addrstr, INET6_ADDRSTRLEN);
            Log(LOG_DEBUG, " %d: %s %d\n", hopcount+1, addrstr,
                    ntohl(hop->rtt));
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


//XXX can we avoid having declarations please?
static void probe_timeout_callback(wand_event_handler_t *ev_hdl, void *data);

/*
 *
 */
static void version(char *prog) {
    fprintf(stderr, "%s, amplet version %s, protocol version %d\n", prog,
            PACKAGE_STRING, AMP_TRACEROUTE_TEST_VERSION);
}



static void send_probe_callback(wand_event_handler_t *ev_hdl, void *data) {
    struct probe_list_t *probelist = (struct probe_list_t*)data;
    struct dest_info_t *item;
    long int delay;

    //printf("send_probe_callback\n");

    /* do nothing if there are no packets to send */
    if ( probelist->ready == NULL ) {
        printf("no packet to send\n");
        return;
    }

    /* remove probe info from the ready list */
    item = probelist->ready;
    probelist->ready = probelist->ready->next;
    if ( probelist->ready == NULL ) {
        probelist->ready_end = NULL;
    }
    item->next = NULL;

    /* send probe to the destination at the appropriate TTL */
    if ( send_probe(probelist->sockets, probelist->ident, item) < 0 ) {
        printf("failed to send probe\n");
        item->next = probelist->done;
        probelist->done = item;
        if ( probelist->outstanding == NULL && probelist->ready == NULL ) {
            ev_hdl->running = 0;
            return;
        }
    } else {
        /* set a timeout if one hasn't already been set for an earlier probe */
        // XXX probelist->timeout == NULL?
        if ( probelist->outstanding == NULL ) {
            //printf("adding first timeout for probe to destination %d\n",
            //        item->id);
            probelist->outstanding = item;
            probelist->outstanding_end = item;
            probelist->timeout =
                wand_add_timer(ev_hdl, 5/* XXX*/, 0, data,
                        probe_timeout_callback);
        } else {
            //printf("not updating timeout for destination %d/%d, oldest probe still outstanding\n", item->id, item->ttl);
            probelist->outstanding_end->next = item;
            probelist->outstanding_end = item;
        }
    }

    /* schedule the next probe to be sent */
    if ( probelist->ready != NULL ) {
        //printf("rescheduling next probe packet\n");
        wand_add_timer(ev_hdl, 0, MIN_INTER_PACKET_DELAY, data,
                send_probe_callback);
    } else {
        //printf("no more packets, leaving send packet timer off\n");
    }
}



static void recv_probe4_callback(wand_event_handler_t *ev_hdl,
                                int fd, void *data, enum wand_eventtype_t ev) {
    char packet[2048];
    struct timeval now;
    struct probe_list_t *probelist = (struct probe_list_t*)data;
    struct sockaddr_in addr;
    socklen_t socklen = sizeof(addr);

    //printf("recv_probe4_callback\n");

    recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&addr, &socklen);
    gettimeofday(&now, NULL);
    //if ( process_ipv4_packet(packet, now, data) > 0 ) {
    if ( process_packet(AF_INET, (struct sockaddr*)&addr, packet, now,
                data) > 0 ) {
        //printf("recv_probe4 enabling send timer\n");
        wand_add_timer(ev_hdl, 0, MIN_INTER_PACKET_DELAY, data,
                send_probe_callback);
    }

    if ( probelist->outstanding == NULL ) {
        if ( probelist->timeout ) {
            wand_del_timer(ev_hdl, probelist->timeout);
            probelist->timeout = NULL;
        }
        if ( probelist->ready == NULL ) {
            ev_hdl->running = 0;
        }
    }
}

static void recv_probe6_callback(wand_event_handler_t *ev_hdl,
                                int fd, void *data, enum wand_eventtype_t ev) {
    char packet[2048];
    struct timeval now;
    struct sockaddr_in6 addr;
    struct probe_list_t *probelist = (struct probe_list_t*)data;
    socklen_t socklen = sizeof(addr);

    //printf("recv_probe6_callback\n");

    recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&addr, &socklen);
    gettimeofday(&now, NULL);
    /* TODO get a full ipv6 header so we can treat them the same? */
    //if ( process_ipv6_packet(packet, &addr, now, data) > 0 ) {
    if ( process_packet(AF_INET6, (struct sockaddr*)&addr, packet, now,
                data) > 0 ) {
        //printf("recv_probe6 enabling send timer\n");
        wand_add_timer(ev_hdl, 0, MIN_INTER_PACKET_DELAY, data,
                send_probe_callback);
    }

    if ( probelist->outstanding == NULL ) {
        if ( probelist->timeout ) {
            wand_del_timer(ev_hdl, probelist->timeout);
            probelist->timeout = NULL;
        }
        if ( probelist->ready == NULL ) {
            ev_hdl->running = 0;
        }
    }
}


static void probe_timeout_callback(wand_event_handler_t *ev_hdl, void *data) {
    struct probe_list_t *probelist = (struct probe_list_t*)data;
    struct dest_info_t *item;
    //printf("probe_timeout_callback\n");

    assert(probelist->outstanding);
    assert(probelist->outstanding_end);

    probelist->timeout = NULL;//XXX move to top of function?

    /* resend this probe if it hasn't already failed too many times */
    if ( inc_attempt_counter(probelist->outstanding) ) {
        printf("attempts %d to destination %d, will retry\n",
                probelist->outstanding->attempts,
                probelist->outstanding->id);
        item = probelist->outstanding;
        probelist->outstanding = probelist->outstanding->next;
        item->next = NULL;

        /* TODO make appending function */
        if ( probelist->ready == NULL ) {
            probelist->ready = item;
            probelist->ready_end = item;
            /* XXX in 100usec, or just do it now? or always have timer firing */
            //printf("probe_timeout enabling send timer\n");
            wand_add_timer(ev_hdl, 0, MIN_INTER_PACKET_DELAY, data,
                    send_probe_callback);
        } else {
            probelist->ready_end->next = item;
            probelist->ready_end = item;
        }
    } else {
        /* no response at first hop, stop probing backwards */
        item = probelist->outstanding;
        probelist->outstanding = probelist->outstanding->next;
        if ( probelist->outstanding == NULL ) {
            probelist->outstanding_end = NULL;
        }
        item->done_backward = 1;
        item->next = probelist->done;
        probelist->done = item;
    }

    /* update timeout to be the next most outstanding packet */
    if ( probelist->outstanding != NULL ) {
        struct timeval now, next;
        item = probelist->outstanding;

        now = wand_get_walltime(ev_hdl);
        next.tv_sec = item->hop[item->ttl - 1].time_sent.tv_sec + 5;/* XXX*/
        next.tv_usec = item->hop[item->ttl - 1].time_sent.tv_usec;

        //printf("now: %d.%06d\n", now.tv_sec, now.tv_usec);
        //printf("time destination %d should expire: %d.%06d\n", item->id,
        //        next.tv_sec, next.tv_usec);

        /* XXX what does a negative result (timeout already expired) look
         * like? Just trigger immediately
         */
        if ( timercmp(&next, &now, <) ) {
            //printf("next timeout now\n");
            probe_timeout_callback(ev_hdl, data);
            return;
        }

        timersub(&next, &now, &next); //XXX can use same as target?

        //printf("next timeout in %d.%d\n", next.tv_sec, next.tv_usec);

        probelist->timeout =
            wand_add_timer(ev_hdl, next.tv_sec, next.tv_usec, data,
                    probe_timeout_callback);
    } else {
        if ( probelist->ready == NULL ) {
            ev_hdl->running = 0;
        }
    }
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
    struct addrinfo *sourcev4, *sourcev6;
    char *device;

    Log(LOG_DEBUG, "Starting TRACEROUTE test");

    /* set some sensible defaults */
    options.packet_size = DEFAULT_TRACEROUTE_PROBE_LEN;
    options.random = 0;
    options.perturbate = 0;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "hvI:p:rs:S:4:6:",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4': sourcev4 = get_numeric_address(optarg, NULL); break;
            case '6': sourcev6 = get_numeric_address(optarg, NULL); break;
            case 'I': device = optarg; break;
	    case 'p': options.perturbate = atoi(optarg); break;
	    case 'r': options.random = 1; break;
	    case 's': options.packet_size = atoi(optarg); break;
            case 'v': version(argv[0]); exit(0);
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

    if ( device && bind_sockets_to_device(&ip_sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw ICMP socket to device, aborting test");
        exit(-1);
    }

    if ( (sourcev4 || sourcev6) &&
            bind_sockets_to_address(&ip_sockets, sourcev4, sourcev6) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw ICMP socket to address, aborting test");
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

{
    struct probe_list_t probelist;
    wand_event_handler_t *ev_hdl;

    probelist.count = count;
    probelist.ident = ident;
    probelist.ready = NULL;
    probelist.ready_end = NULL;
    probelist.outstanding = NULL;
    probelist.outstanding_end = NULL;
    probelist.done = NULL;
    probelist.sockets = &ip_sockets;
    probelist.timeout = NULL;

    /* create all info blocks and place them in the send queue */
    for ( i = 0; i < count; i++ ) {
        struct dest_info_t *item =
            (struct dest_info_t*)calloc(1, sizeof(struct dest_info_t));
        item->addr = dests[i];
        item->ttl = INITIAL_TTL;
        item->id = i;
        item->next = NULL;
        append_ready_item(&probelist, item);
    }

    wand_event_init();
    ev_hdl = wand_create_event_handler();

    /* set up callbacks for receiving packets */
    wand_add_fd(ev_hdl, icmp_sockets.socket, EV_READ, &probelist,
            recv_probe4_callback);

    wand_add_fd(ev_hdl, icmp_sockets.socket6, EV_READ, &probelist,
            recv_probe6_callback);

    /* set up timer to send packets */
    wand_add_timer(ev_hdl, 0, MIN_INTER_PACKET_DELAY, &probelist,
            send_probe_callback);

    wand_event_run(ev_hdl);

    assert(probelist.ready == NULL);
    assert(probelist.ready_end == NULL);
    assert(probelist.outstanding == NULL);
    assert(probelist.outstanding_end == NULL);
    assert(probelist.done);

    wand_destroy_event_handler(ev_hdl);

    /* XXX probelists get lost here because of temporary scoping */
    report_results(&start_time, count, probelist.done, &options);

    {
        struct dest_info_t *item;
        char addrstr[INET6_ADDRSTRLEN];
        for ( item = probelist.done; item != NULL; item = item->next ) {
            if ( item->addr->ai_family == AF_INET ) {
                inet_ntop(item->addr->ai_family,
                        &((struct sockaddr_in*)item->addr->ai_addr)->sin_addr,
                        addrstr, INET6_ADDRSTRLEN);
            } else {
                inet_ntop(item->addr->ai_family,
                        &((struct sockaddr_in6*)item->addr->ai_addr)->sin6_addr,
                        addrstr, INET6_ADDRSTRLEN);
            }
            printf("%d %s: %d\n", item->id, addrstr, item->probes);
        }
    }
}

printf("SENT %d PACKETS\n", total_packets);

    /* sockets aren't needed any longer */
    if ( icmp_sockets.socket > 0 ) {
	close(icmp_sockets.socket);
	close(ip_sockets.socket);
    }

    if ( icmp_sockets.socket6 > 0 ) {
	close(icmp_sockets.socket6);
	close(ip_sockets.socket6);
    }

    if ( sourcev4 ) {
        freeaddrinfo(sourcev4);
    }

    if ( sourcev6 ) {
        freeaddrinfo(sourcev6);
    }

    /* send report */
#if 0
    report_results(&start_time, count, info, &options);
    /* tidy up */
    for ( i = 0; i < count; i++ ) {
        for ( hop = 0; hop < MAX_HOPS_IN_PATH; hop++ ) {
            if ( info[i].hop[hop].reply ) {
                /* we've allocated ai_addr ourselves, so have to free it */
                /* TODO: freeing this data without the explicit checks for
                 * NULL was causing segfaults, but I can't see a way for these
                 * not to be set if reply is set? Reply is set immediately
                 * before allocating this memory.
                 */
                if ( info[i].hop[hop].addr->ai_addr != NULL ) {
                    free(info[i].hop[hop].addr->ai_addr);
                }
                /* XXX freeaddrinfo should deal with freeing ai_addr too? */
                if ( info[i].hop[hop].addr != NULL ) {
                    freeaddrinfo(info[i].hop[hop].addr);
                }
            }
        }
    }
    free(info);
#endif
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
    int i, offset;
    int hopcount;
    char *ampname;

    assert(data != NULL);
    assert(len >= sizeof(struct traceroute_report_header_t));
    assert(ntohl(header->version) == AMP_TRACEROUTE_TEST_VERSION);

    printf("\n");
    printf("AMP traceroute test, %u destinations, %u byte packets ",
            header->count, ntohs(header->packet_size));
    if ( header->random ) {
	printf("(random size)\n");
    } else {
	printf("(fixed size)\n");
    }

    offset = sizeof(struct traceroute_report_header_t);

    for ( i=0; i<header->count; i++ ) {
        /* specific path information */
        path = (struct traceroute_report_path_t*)(data + offset);
        offset += sizeof(struct traceroute_report_path_t);

        ampname = (char *)data + offset;
        offset += path->namelen;

        printf("\n");
	printf("%s", ampname);
	inet_ntop(path->family, path->address, addrstr, INET6_ADDRSTRLEN);
	printf(" (%s)\n", addrstr);

        /* per-hop information for this path */
        for ( hopcount = 0; hopcount < path->length; hopcount++ ) {
           hop = (struct traceroute_report_hop_t*)(data + offset);
           offset += sizeof(struct traceroute_report_hop_t);

           inet_ntop(path->family, hop->address, addrstr, INET6_ADDRSTRLEN);
           printf(" %.2d  %s %dus", hopcount+1, addrstr, ntohl(hop->rtt));
           if ( path->err_type > 0 ) {
                printf(" error: %d/%d", path->err_type, path->err_code);
           }
           printf("\n");
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
    new_test->max_duration = 300;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_traceroute;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_traceroute;

    /* the traceroute test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    return new_test;
}


#if UNIT_TEST
int amp_traceroute_build_ipv4_probe(void *packet, uint16_t packet_size, int id,
        int ttl, uint16_t ident, struct addrinfo *dest) {
    return build_ipv4_probe(packet, packet_size, id, ttl, ident, dest);
}

int amp_traceroute_build_ipv6_probe(void *packet, uint16_t packet_size, int id,
        uint16_t ident, struct addrinfo *dest) {
    return build_ipv6_probe(packet, packet_size, id, ident, dest);
}
#endif
