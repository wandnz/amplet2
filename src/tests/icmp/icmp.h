#ifndef _TESTS_ICMP_H
#define _TESTS_ICMP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_ICMP_TEST_VERSION 2013121800

/* by default use an 84 byte packet, because that's what it has always been */
#define DEFAULT_ICMP_ECHO_REQUEST_LEN 84

/* targets can mix ipv4 and ipv6, so use ipv6 len to calc min packet size */
#define IP_HEADER_LEN (sizeof(struct ip6_hdr))

/* minimum size of the icmp portion is the header plus "magic" data */
#define MIN_ICMP_ECHO_REQUEST_LEN (sizeof(struct icmphdr) + sizeof(uint16_t))

/* timeout in usec to wait before declaring the response lost, currently 20s */
#define LOSS_TIMEOUT 20000000


int run_icmp(int argc, char *argv[], int count, struct addrinfo **dests);
int save_icmp(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_icmp(void *data, uint32_t len);
test_t *register_test(void);

/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    int random;			/* use random packet sizes (bytes) */
    int perturbate;		/* delay sending by up to this time (usec) */
    uint16_t packet_size;	/* use this packet size (bytes) */
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
    uint8_t ttl;		/* TTL or hop limit of response packet */
};


struct icmp_report_item_t {
    /* nicer way than storing just 16 bytes for the address? */
    char address[16];
    int32_t rtt;
    uint8_t family;
    uint8_t err_type;
    uint8_t err_code;
    uint8_t ttl;
    /* XXX do we want to add 7 bytes of padding here before namelen? */
    /* XXX byte ordering */
    char reserved[7];
    uint8_t namelen;
};

struct icmp_report_header_t {
    uint32_t version;
    uint16_t packet_size;
    uint8_t random;
    uint8_t count;
};

#endif
