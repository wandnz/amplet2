#ifndef _TESTS_ICMP_H
#define _TESTS_ICMP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_ICMP_TEST_VERSION 2014020300

/* by default use an 84 byte packet, because that's what it has always been */
#define DEFAULT_ICMP_ECHO_REQUEST_LEN 84

/*
 * We can mix ipv4 and ipv6 targets in our tests, so set the minimum packet
 * size to be the ipv6 header length + icmp header length + our "magic" two
 * bytes that are used to store test information.
 */
#define MIN_PACKET_LEN ( \
        sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(uint16_t))

/*
 * Initial ipv4 hlen + maximum ipv4 hlen + response icmp header + 8 bytes.
 * We don't get the ipv6 header, so the ipv4 version is the bigger of the two.
 */
#define RESPONSE_BUFFER_LEN ( \
        sizeof(struct iphdr) + 60 + sizeof(struct icmphdr) + 8)

/* timeout in usec to wait before declaring the response lost, currently 20s */
#define LOSS_TIMEOUT 20000000



/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    int random;			/* use random packet sizes (bytes) */
    int perturbate;		/* delay sending by up to this time (usec) */
    uint8_t dscp;               /* diffserv codepoint to set */
    uint16_t packet_size;	/* use this packet size (bytes) */
    uint32_t inter_packet_delay;/* minimum gap between packets (usec) */
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


amp_test_result_t* run_icmp(int argc, char *argv[], int count,
        struct addrinfo **dests);
int save_icmp(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_icmp(amp_test_result_t *result);
test_t *register_test(void);
#if UNIT_TEST
uint16_t amp_test_icmp_checksum(uint16_t *packet, int size);
int amp_test_process_ipv4_packet(char *packet, uint32_t bytes, uint16_t ident,
        struct timeval now, int count, struct info_t info[]);
void amp_test_report_results(struct timeval *start_time, int count,
        struct info_t info[], struct opt_t *opt);
#endif


#endif
