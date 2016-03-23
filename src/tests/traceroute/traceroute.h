#ifndef _TESTS_TRACEROUTE_H
#define _TESTS_TRACEROUTE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip6.h>

#include "tests.h"
#include "testlib.h"

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_TRACEROUTE_TEST_VERSION 2014080700

#define DEFAULT_TRACEROUTE_PROBE_LEN 60

#define MIN_TRACEROUTE_PROBE_LEN (sizeof(struct ip6_hdr) + \
        sizeof(struct udphdr) + sizeof(struct ipv6_body_t))

/* timeout in seconds to wait before declaring a response lost, currently 2s */
#define LOSS_TIMEOUT 2
#define LOSS_TIMEOUT_US (LOSS_TIMEOUT * 1000000)

/* TODO we can do this better than a fixed size buffer */
#define MAX_HOPS_IN_PATH 30

/* Destination port for the UDP probe packets */
#define TRACEROUTE_DEST_PORT 33434

/* TTL to use for the first probe packet */
#define INITIAL_TTL 3

/* Maximum number of destinations that can have probe packets outstanding */
#define INITIAL_WINDOW 50

/* number of times to try at a particular TTL to elicit a response */
#define TRACEROUTE_RETRY_LIMIT 2

/* number of consecutive timeouts required before giving up on a path */
#define TRACEROUTE_NO_REPLY_LIMIT 5

/* TTL marker for probing full path length */
#define TRACEROUTE_FULL_PATH_PROBE_TTL (-5)

#define HOP_ADDR(ttl) (item->hop[ttl - 1].addr)
#define HOP_REPLY(ttl) (item->hop[ttl - 1].reply)

amp_test_result_t* run_traceroute(int argc, char *argv[], int count,
        struct addrinfo **dests);
int save_traceroute(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_traceroute(amp_test_result_t *result);
test_t *register_test(void);
int compare_addresses(const struct sockaddr *a,
        const struct sockaddr *b, int len);

#if UNIT_TEST
int amp_traceroute_build_ipv4_probe(void *packet, uint16_t packet_size,
        uint8_t dscp, int id, int ttl, uint16_t ident, struct addrinfo *dest);
int amp_traceroute_build_ipv6_probe(void *packet, uint16_t packet_size, int id,
        uint16_t ident, struct addrinfo *dest);
#endif


/*
 * Used to describe responses - if the stopset is used then some addresses
 * listed in a path may not have been actually observed.
 */
typedef enum {
    REPLY_UNKNOWN = 0,
    REPLY_TIMED_OUT,
    REPLY_OK,
    REPLY_ASSUMED_STOPSET,
} reply_t;

/*
 * Packet structure used in the body of IPv6 packets, it's easier to do it
 * this way than to create and send an entire packet ourselves.
 */
struct ipv6_body_t {
    uint16_t index;
    uint16_t ident;
};

/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    int random;			/* use random packet sizes (bytes) */
    int perturbate;		/* delay sending by up to this time (usec) */
    int probeall;               /* probe every path in full */
    int ip;                     /* report the IP address of each hop */
    int as;                     /* lookup the AS number of each address */
    uint16_t packet_size;	/* use this packet size (bytes) */
    uint32_t inter_packet_delay;/* minimum gap between packets (usec) */
    uint8_t dscp;
};

/*
 * Information block for the probe sent to a particular TTL.
 */
struct hop_info_t {
    struct timeval time_sent;	/* when the probe was sent */
    int64_t as;                 /* AS that the address belongs to */
    uint32_t delay;		/* delay in receiving response, microseconds */
    reply_t reply;              /* Has a reply been received */
    struct addrinfo *addr;      /* Address that the reply came from */
};

/*
 * Information block recording data for the UDP probe packets sent to a single
 * destination.
 */
typedef struct dest_info_t dest_info_t;
struct dest_info_t {
    struct addrinfo *addr;      /* address probe was sent to */
    uint32_t id;                /* ID number of destination */
    uint32_t probes;            /* number of probes sent so far */
    int8_t first_response;      /* TTL of first response packet */
    int8_t ttl;                 /* current TTL being probed */
    uint8_t path_length;        /* total length of path, once confirmed */
    uint8_t done_forward;       /* true if forward probing has finished */
    uint8_t done_backward;      /* true if backwards probing has finished */
    uint8_t attempts;           /* number of probe attempts at this TTL */
    uint8_t no_reply_count;     /* number of probes sent without response */
    uint8_t err_type;           /* ICMP response error type (0 if success) */
    uint8_t err_code;           /* ICMP response error code */
    struct hop_info_t hop[MAX_HOPS_IN_PATH];
    struct dest_info_t *next;
};


/*
 * Stopset item to record addresses close to the monitor that have already
 * been probed, and what the rest of the path should be.
 */
typedef struct stopset_t stopset_t;
struct stopset_t {
    uint8_t ttl;
    uint8_t family;
    uint32_t delay;
    struct sockaddr *addr;
    struct stopset_t *next;
    struct stopset_t *path;
};

/* XXX need better names */
struct probe_list_t {
    struct socket_t *sockets;
    struct dest_info_t *pending;
    struct dest_info_t *ready;
    struct dest_info_t *ready_end;
    struct dest_info_t *outstanding;
    struct dest_info_t *outstanding_end;
    struct dest_info_t *done;
    struct stopset_t *stopset;
    struct wand_timer_t *timeout;
    uint32_t count;
    uint32_t done_count;
    uint16_t ident;
    struct opt_t *opts;
    int window;
    int total_probes;
};

#endif
