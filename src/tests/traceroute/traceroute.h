#ifndef _TESTS_TRACEROUTE_H
#define _TESTS_TRACEROUTE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_TRACEROUTE_TEST_VERSION 2013032800

#define DEFAULT_TRACEROUTE_PROBE_LEN 60

#define MIN_TRACEROUTE_PROBE_LEN (sizeof(struct ip6_hdr) + \
        sizeof(struct udphdr) + sizeof(struct ipv6_body_t))

/* timeout in usec to wait before declaring the response lost, currently 5s */
/* TODO this used to be 20s, if we make it too short do we break stuff? */
#define LOSS_TIMEOUT 5000000

/* TODO we can do this better than a fixed size buffer */
#define MAX_HOPS_IN_PATH 30

#define TRACEROUTE_DEST_PORT 33434

/* number of times to try at a particular TTL to elicit a response */
#define TRACEROUTE_RETRY_LIMIT 2

/* number of consecutive timeouts required before giving up on a path */
#define TRACEROUTE_NO_REPLY_LIMIT 5

/* TTL marker for probing full path length */
#define TRACEROUTE_FULL_PATH_PROBE_TTL (-5)

#define HOP_ADDR(index,ttl) (info[index].hop[ttl - 1].addr)
#define HOP_REPLY(index,ttl) (info[index].hop[ttl - 1].reply)

int run_traceroute(int argc, char *argv[], int count, struct addrinfo **dests);
int save_traceroute(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_traceroute(void *data, uint32_t len);
test_t *register_test(void);


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
    uint16_t packet_size;	/* use this packet size (bytes) */
};

struct hop_info_t {
    struct timeval time_sent;	/* when the probe was sent */
    uint32_t delay;		/* delay in receiving response, microseconds */
    uint8_t reply;
    struct addrinfo *addr;
};

/*
 * Information block recording data for each icmp echo request test packet
 * that is sent, and when the response is received.
 */
struct info_t {
    struct timeval last_time_sent;	/* when the probe was sent */
    struct addrinfo *addr;	/* address probe was sent to */
    int8_t ttl;		        /* TTL or hop limit of response packet */
    uint8_t path_length;
    uint8_t done;
    uint8_t retry;
    uint8_t attempts;
    uint8_t no_reply_count;
    uint8_t err_type;		/* type of ICMP error reply or 0 if no error */
    uint8_t err_code;		/* code of ICMP error reply, else undefined */
    struct hop_info_t hop[MAX_HOPS_IN_PATH];
};

struct traceroute_report_hop_t {
    char address[16];
    int32_t rtt;
    uint32_t reserved;
};

struct traceroute_report_path_t {
    /* TODO make the name field variable length? */
    char name[128];
    /* nicer way than storing just 16 bytes for the address? */
    char address[16];
    uint32_t reserved;
    uint8_t family;
    uint8_t length;
    uint8_t err_type;
    uint8_t err_code;
};

struct traceroute_report_header_t {
    uint32_t version;
    uint16_t packet_size;
    uint8_t random;
    uint8_t count;
};

#endif
