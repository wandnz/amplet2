#ifndef _TESTS_TCPPING_H_
#define _TESTS_TCPPING_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <libwandevent.h>

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_TCPPING_TEST_VERSION 2014072100

/* use the same packet size as ICMP, so we're directly comparable */
#define DEFAULT_TCPPING_SYN_LENGTH 84

/* The '4' here is to allow us to at least include an MSS option in
 * the SYN that we send.
 */
#define MIN_PACKET_LEN ( \
    sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + 4)


/* Generally, we only need the TCP header of the response (no options) but
 * if we get an ICMP response we'll need enough space to store the headers
 * from the original packet... */
#define RESPONSE_BUFFER_LEN (300)

/* timeout in sec to wait before declaring the response lost, currently 10s */
#define LOSS_TIMEOUT 10

/*
 * User defined test options to control packet size and timing.
 */
struct opt_t {
    int random;             /* Use random packet sizes (bytes) */
    int perturbate;         /* Delay sending by up to this time (usec) */
    uint16_t packet_size;   /* Use this particular packet size (bytes) */
    uint16_t port;          /* Target port number */
};

struct tcppingglobals {
    struct opt_t options;
    int seqindex;
    struct addrinfo **dests;
    struct addrinfo *sourcev4;
    struct addrinfo *sourcev6;
    uint16_t sourceportv4;
    uint16_t sourceportv6;
    struct socket_t raw_sockets;
    struct socket_t tcp_sockets;
    struct info_t *info;
    int destindex;
    int destcount;
    char *device;
    int outstanding;

    struct wand_timer_t *nextpackettimer;
    struct wand_timer_t *losstimer;
};


/* Pseudoheader for TCP checksum, IPv4 */
struct pseudotcp_ipv4 {
    uint32_t saddr, daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

/* Pseudoheader for TCP checksum, IPv6 */
struct pseudotcp_ipv6 {
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint32_t length;
    uint16_t zero_1;
    uint8_t zero_2;
    uint8_t next;
};

struct tcpmssoption {
    uint8_t mssopt;
    uint8_t msssize;
    uint16_t mssvalue;
};

/* 
 * Describes each SYN packet that was sent and the response that was
 * received.
 */
struct info_t {
    struct sockaddr_storage source; /* Source IP address for the probe */
    struct addrinfo *addr;      /* Address that was probed */
    struct timeval time_sent;   /* Time when the SYN was sent */
    uint32_t seqno;             /* Sequence number of the sent SYN */
    uint32_t delay;             /* Delay in receiving response */
    uint8_t reply;              /* Set to 1 if the reply was a TCP packet, 
                                 * 2 if the reply was an ICMP packet */
    uint8_t replyflags;         /* TCP control bits set in the reply */
    uint8_t icmptype;           /* ICMP type of the reply */
    uint8_t icmpcode;           /* ICMP code of the reply */
};

struct tcpping_report_item_t {
    char address[16];
    int32_t rtt;
    uint8_t family;
    uint8_t reply;
    uint8_t replyflags;
    uint8_t icmptype;
    uint8_t icmpcode;
    uint8_t namelen;
} __attribute__((__packed__));

struct tcpping_report_header_t {
    uint32_t version;
    uint16_t packet_size;
    uint16_t port;
    uint8_t random;
    uint8_t count;
} __attribute__((__packed__));

int run_tcpping(int argc, char *argv[], int count, struct addrinfo **dests);
int save_tcpping(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_tcpping(void *data, uint32_t len);
test_t *register_test(void);


#endif

/* vim: set sw=4 tabstop=4 softtabstop=4 expandtab : */
