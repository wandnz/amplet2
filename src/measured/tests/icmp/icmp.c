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

#include "debug.h"


/* by default use an 84 byte packet, because that's what it has always been */
#define DEFAULT_ICMP_ECHO_REQUEST_LEN 84

/* targets can mix ipv4 and ipv6, so use ipv6 len to calc minimum packet size */
#define IP_HEADER_LEN (sizeof(struct ip6_hdr))

/* minimum size of the icmp portion is the header plus "magic" data */
#define MIN_ICMP_ECHO_REQUEST_LEN (sizeof(struct icmphdr) + sizeof(uint16_t))

/* timeout in usec to wait before declaring the response lost, currently 20s */
#define LOSS_TIMEOUT 20000000

/* minimum time in usec allowed between sending test packets */
#define MIN_INTER_PACKET_DELAY 100


// XXX these should be in a library somewhere 
#define US_FROM_US(x) ((x) % 1000000)
#define S_FROM_US(x)  ((int)((x)/1000000))
#define DIFF_TV_US(tva, tvb) ( (((tva).tv_sec - (tvb).tv_sec) * 1000000) + \
                              ((tva).tv_usec - (tvb).tv_usec) )


/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    int random;			/* use random packet sizes (bytes) */
    int perturbate;		/* delay sending by up to this time (usec) */
    uint16_t packet_size;	/* use this packet size (bytes) */
};



/*
 * Structure combining the ipv4 and ipv6 network sockets so that they can be
 * passed around and operated on together as a single item.
 */
struct socket_t {
    int socket;			/* ipv4 socket, if available */
    int socket6;		/* ipv6 socket, if available */
};



/*
 * Information block recording data for each icmp echo request test packet 
 * that is sent, and when the response is received.
 */
struct info_t {
    struct addrinfo *addr;	/* address probe was sent to */
    struct timeval time_sent;	/* when the probe was sent */
    uint32_t delay;		/* delay in receiving response, microseconds */
    uint16_t magic;		/* a random number to confirm response */
    uint8_t reply;		/* set to 1 once we have a reply */
    uint8_t err_type;		/* type of ICMP error reply or 0 if no error */
    uint8_t err_code;		/* code of ICMP error reply, else undefined */
};



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
 * TODO this may want to move out into a library so it can be reused
 */
/*
 * Given a pair of sockets (ipv4 and ipv6), wait for data to arrive on either
 * of them, up to maxwait microseconds. If data arrives before the timeout
 * then return which socket received the data, otherwise -1.
 */
static int wait_for_data(struct socket_t *sockets, int *maxwait) {
    struct timeval start_time, end_time;
    struct timeval timeout;
    int delay;
    int max_fd;
    int ready;
    fd_set readset;

    gettimeofday(&start_time, NULL);

    max_fd = -1;
    delay = 0;

    do {
	/* 
	 * if there has been an error then update timeout by how long we have
	 * already taken so we can carry on where we left off
	 */
	if ( delay > *maxwait ) {
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 0;
	} else {
	    timeout.tv_sec = S_FROM_US(*maxwait - delay);
	    timeout.tv_usec = US_FROM_US(*maxwait - delay);
	}

	/* fd sets are undefined after an error, so set them every time too */
	FD_ZERO(&readset);
	if ( sockets->socket > 0 ) {
	    FD_SET(sockets->socket, &readset);
	    max_fd = sockets->socket;
	}

	if ( sockets->socket6 > 0 ) {
	    FD_SET(sockets->socket6, &readset);
	    if ( sockets->socket6 > max_fd ) {
		max_fd = sockets->socket6;
	    }
	}
	
	ready = select(max_fd+1, &readset, NULL, NULL, &timeout);
	
	/* 
	 * we can't always trust the value of timeout after select returns, so
	 * check for ourselves how much time has elapsed
	 */
	gettimeofday(&end_time, NULL);
	delay = DIFF_TV_US(end_time, start_time);

	/* if delay is less than zero then maybe the clock was adjusted on us */
	if ( delay < 0 ) {
	    delay = 0;
	}

	/* continue until there is data to read or we get a non EINTR error */
    } while ( ready < 0 && errno == EINTR );

    /* remove the time waited so far from maxwait */
    *maxwait -= delay;
    if ( *maxwait < 0 ) {
	*maxwait = 0;
    }

    /* if there was a non-EINTR error then report it */
    if ( ready < 0 ) {
	Log(LOG_WARNING, "select() failed");
	return -1;
    }

    /* return the appropriate socket that has data waiting */
    if ( sockets->socket > 0 && FD_ISSET(sockets->socket, &readset) ) {
	return AF_INET;
    }
    
    if ( sockets->socket6 > 0 && FD_ISSET(sockets->socket6, &readset) ) {
	return AF_INET6;
    }

    return -1;
}



/*
 * TODO this may want to move out into a library so it can be reused
 */
/*
 * Wait for up to timeout microseconds to receive a packet on the given 
 * sockets and return the number of bytes read.
 */
static int get_packet(struct socket_t *sockets, char *buf, int len, 
	struct sockaddr *saddr, int *timeout) {

    int bytes;
    int sock;
    int family;
    socklen_t addrlen;

    /* wait for data to be ready to read, up to timeout (wait will update it) */
    if ( (family = wait_for_data(sockets, timeout)) <= 0 ) {
	return 0;
    }

    /* determine which socket we have received data on and read from it */
    switch ( family ) {
	case AF_INET: sock = sockets->socket; 
		      addrlen = sizeof(struct sockaddr_in); 
		      break;
	case AF_INET6: sock = sockets->socket6;
		       addrlen = sizeof(struct sockaddr_in6);
		       break;
	default: return 0;
    };

    if ( (bytes = recvfrom(sock, buf, len, 0, saddr, &addrlen)) < 0 ) {
	Log(LOG_ERR, "Failed to recvfrom()");
	exit(-1);
    }

    return bytes;
}



static int delay_send_packet(int sock, char *packet, int size, 
	struct addrinfo *dest) {

    int bytes_sent;
    static struct timeval last = {0, 0};
    struct timeval now;
    int delay;

    gettimeofday(&now, NULL);

    /* determine how much time is left to wait until the minimum delay */
    if ( last.tv_sec != 0 && DIFF_TV_US(now, last) < MIN_INTER_PACKET_DELAY ) {
	delay = MIN_INTER_PACKET_DELAY - DIFF_TV_US(now, last);
    } else {
	delay = 0;
	last.tv_sec = now.tv_sec;
	last.tv_usec = now.tv_usec;
    }

    /* 
     * if there is still time to wait before the next packet then return
     * control to the caller, in case they want to do more work while waiting
     */
    if ( delay != 0 ) {
	return delay;
    }

    bytes_sent = sendto(sock, packet, size, 0, dest->ai_addr, dest->ai_addrlen);

    /* TODO determine error and/or send any unsent bytes */
    if ( bytes_sent != size ) {
	Log(LOG_ERR, "Only sent %d of %d bytes", bytes_sent, size);
    }

    return 0;
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
	Log(LOG_WARNING, "ICMP reply too small for embedded packet data");
	return;
    }

    /* get the embedded ip header */
    embed_ip = (struct iphdr *)packet + ((ip->ihl << 2) +
	    sizeof(struct icmphdr));

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
    info[seq].err_type = icmp->type;
    info[seq].err_code = icmp->code;
    info[seq].reply = 1;

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

    char packet[1024]; //XXX can we be sure of a max size for recv packets?
    struct timeval now;
    struct sockaddr_in6 addr;//XXX why is this a 6

    /* read packets until we hit the timeout, or we have all we expect.
     * Note that wait is reduced by get_packet()
     */
    while ( get_packet(raw_sockets, packet, 1024, (struct sockaddr*)&addr, 
		&wait) ) {
	gettimeofday(&now, NULL);

	switch ( ((struct iphdr*)packet)->version ) {
	    case 4: process_ipv4_packet(packet, ident, now, count, info); break;
	    case 6: process_ipv6_packet(packet, ident, now, count, info); break;
	    default: break; 
	};
    }
}



/* XXX do we care about minimum inter packet delay? 
 * XXX if we don't use it, could we be more likely to count local queuing delay?
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
	Log(LOG_WARNING, "Unable to test to %s, socket wasn't opened", "XXX");
	return;
    }

    /* send packet with appropriate inter packet delay */
    do {
	if ( (delay = delay_send_packet(sock, packet, opt->packet_size-h_len, 
			dest)) > 0 ) {
	    /* check for responses while we wait out the interpacket delay */
	    harvest(raw_sockets, ident, delay, count, info);
	}
    } while ( delay > 0 );

    /* record the time the packet was sent */
    gettimeofday(&(info[seq].time_sent), NULL);
}



/*
 * Open the raw ICMP and ICMPv6 sockets used for this test and configure
 * appropriate filters for the ICMPv6 socket to only receive echo replies.
 */
static int open_sockets(struct socket_t *raw_sockets) {
    if ( (raw_sockets->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 ) {
	Log(LOG_WARNING, "Failed to open raw socket for ICMP");
    }
    
    if ( (raw_sockets->socket6=socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6))<0 ) {
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
static void report(struct timeval start_time, int count, struct info_t info[], 
	struct opt_t *opt) {
    int dest;

    printf("OPTS size:%d, random:%d\n", opt->packet_size, opt->random);
    printf("START: %.6d.%.6d\n",(int)start_time.tv_sec,(int)start_time.tv_usec);

    for ( dest = 0; dest < count; dest ++ ) {
	/* FIXME just print ipv4 for testing */
	char foo[1024];
	inet_ntop(info[dest].addr->ai_family, 
		&((struct sockaddr_in*)info[dest].addr->ai_addr)->sin_addr, 
		foo, info[dest].addr->ai_addrlen);
	printf("%s: ", foo);
	if ( info[dest].reply ) {
	    /* FIXME the old icmp test truncates to milliseconds here */
	    printf("%d ", info[dest].delay);
	} else {
	    printf("-1 ");
	}
	printf("%d/%d\n", info[dest].err_type, info[dest].err_code);
    }

    /* TODO send to server somehow */
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
 * TODO check that all the random macros used for values are actually needed
 * TODO get useful errors into the log strings
 * TODO get test name into log strings
 * TODO logging will need more work - the log level won't be set.
 * TODO do destinations properly - stdin or args
 */
int main(int argc, char *argv[]) {
    int opt;
    struct opt_t options;
    struct timeval start_time;
    struct socket_t raw_sockets;
    struct info_t *info;
    int count = 1;//XXX number of destinations
    struct addrinfo *dests;
    int dest;
    uint16_t ident;
    struct addrinfo hint;//XXX

    printf("icmp test\n");

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
    }

    /* make sure that the packet size is big enough for our data */
    if ( options.packet_size < MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN ) {
	Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
		options.packet_size, MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN);
	options.packet_size = MIN_ICMP_ECHO_REQUEST_LEN + IP_HEADER_LEN;	
    }

    /* TODO determinate all destinations */
    /* XXX testing code */
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_flags = AI_NUMERICHOST;
    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = 0;
    hint.ai_protocol = 0;
    hint.ai_addrlen = 0;
    hint.ai_addr = NULL;
    hint.ai_canonname = NULL;
    hint.ai_next = NULL;
    getaddrinfo("130.217.250.16", NULL, &hint, &dests);

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

    ident = (uint16_t)start_time.tv_sec;
    info = (struct info_t *)malloc(sizeof(struct info_t) * count);

    /* TODO send a test packet to each destination */
    for ( dest = 0; dest < count; dest++ ) {
	//send_packet(&raw_sockets, dest, ident, dests[dest], info, &options);
	send_packet(&raw_sockets, dest, ident, dests, count, info, &options);
    }

    /* 
     * harvest results - try with a short timeout to start with, so maybe we
     * can avoid doing the long wait later
     */
    harvest(&raw_sockets, ident, LOSS_TIMEOUT / 100, count, info);
    for ( dest = 0; dest < count && info[dest].reply; dest++ ) { /* nothing */ }
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
    report(start_time, count, info, &options);

    free(info);
    freeaddrinfo(dests);

    return 0;
}
