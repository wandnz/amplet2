#ifndef _TESTS_UDPSTREAM_H
#define _TESTS_UDPSTREAM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <errno.h>

#include "config.h"
#include "tests.h"
#include "udpstream.pb-c.h"


#define AMP_UDPSTREAM_TEST_VERSION 2016011800

// TODO use different ports to the throughput test
/* The default test port */
#define DEFAULT_CONTROL_PORT  8815 /* Could use etc/services like old code */
#define MAX_CONTROL_PORT  8825
#define DEFAULT_TEST_PORT 8826 /* Run test across a separate port */
#define MAX_TEST_PORT 8836

#define MINIMUM_UDPSTREAM_PACKET_COUNT 2
#define MINIMUM_UDPSTREAM_PACKET_LENGTH ( \
        sizeof(struct ip6_hdr) + sizeof(struct udphdr) + \
        sizeof(struct payload_t))
#define MAXIMUM_UDPSTREAM_PACKET_LENGTH 1500
#define DEFAULT_UDPSTREAM_PACKET_LENGTH 100
#define DEFAULT_UDPSTREAM_PACKET_COUNT 11
#define DEFAULT_UDPSTREAM_PERCENTILE_COUNT 10
/* 20ms interval between packets is common for VOIP */
#define DEFAULT_UDPSTREAM_INTER_PACKET_DELAY 20000
#define UDPSTREAM_LOSS_TIMEOUT 2000000


enum udpstream_schedule_direction {
    DIRECTION_NOT_SET = -1,
    CLIENT_TO_SERVER = 0,
    SERVER_TO_CLIENT = 1,
    CLIENT_THEN_SERVER = 2,
    SERVER_THEN_CLIENT = 3,
};

enum udpstream_direction {
    UDPSTREAM_TO_CLIENT = 1,
    UDPSTREAM_TO_SERVER = 2,
};

struct test_request_t {
    enum udpstream_direction direction;
    struct test_request_t *next;
};

/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    uint16_t perturbate;
    uint16_t cport; /* The control port to connect to */
    uint16_t tport; /* The test port to connect to or create */
    uint16_t packet_size;
    uint16_t packet_count;
    uint32_t packet_spacing;
    uint32_t percentile_count;
    uint8_t dscp;
    enum udpstream_schedule_direction direction;
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



/*
 * Payload sent inside the UDP probe packets.
 */
struct payload_t {
    uint64_t sec;
    uint64_t usec;
    uint32_t index;
} __attribute__((__packed__));


test_t *register_test(void);
amp_test_result_t* run_udpstream(int argc, char *argv[], int count,
        struct addrinfo **dests);
void run_udpstream_server(int argc, char *argv[], BIO *ctrl);
amp_test_result_t* run_udpstream_client(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_udpstream(amp_test_result_t *result);
void usage(char *prog);
void version(char *prog);
int send_udp_stream(int sock, struct addrinfo *remote, struct opt_t *options);
int receive_udp_stream(int sock, uint32_t packet_count, struct timeval *times);
Amplet2__Udpstream__Item* report_stream(enum udpstream_direction direction,
        struct timeval *times, struct opt_t *options);

ProtobufCBinaryData* build_hello(struct opt_t *options);
void* parse_hello(ProtobufCBinaryData *data);
ProtobufCBinaryData* build_send(struct opt_t *options);
void* parse_send(ProtobufCBinaryData *data);
#endif
