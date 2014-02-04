#ifndef _TESTS_DNS_H
#define _TESTS_DNS_H

#include "tests.h"

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_DNS_TEST_VERSION 2014020400

/* maximum size in bytes of a DNS name - 255 bytes */
#define MAX_DNS_NAME_LEN MAX_STRING_FIELD

/* timeout in usec to wait before declaring the response lost, currently 20s */
#define LOSS_TIMEOUT 20000000

/* XXX do we want to change these response codes to make more sense? */
#define RESPONSEOK  0
#define MISSING     1
#define INVALID     2
#define NOTFOUND    3



int run_dns(int argc, char *argv[], int count, struct addrinfo **dests);
int save_dns(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_dns(void *data, uint32_t len);
test_t *register_test(void);



/*
 * Our implementation of a DNS header so we can set/check flags etc easily.
 */
union flags_t {
    struct flag_fields_t {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t cd:1;
	uint16_t ad:1;
	uint16_t z:1;
	uint16_t ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t z:1;
	uint16_t ad:1;
	uint16_t cd:1;
	uint16_t rcode:4;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    } fields;
    uint16_t bytes;
} __attribute__((__packed__));

struct dns_t {
    uint16_t id;
    union flags_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
};



/*
 * DNS OPT Resource Record minus the initial arbitrary length name field.
 * This is used by the test to create the pseudo RR header for using DNSSEC
 * or NSID options as well as for processing resource records in the response
 * packets.
 */
struct dns_opt_rr_t {
    //uint8_t name;	    /* empty name */
    uint16_t type;	    /* OPT type */
    uint16_t payload;	    /* normally used for class */
    uint8_t rcode;	    /* normally part of the ttl field */
    uint8_t version;	    /* normally part of the ttl field */
    uint16_t z;		    /* MSB is the DO bit (DNSSEC OK) */
    uint16_t rdlen;	    /* RDATA length */
};



/*
 * DNS query record minus the initial arbitrary length name field. This is 
 * used in the query to describe the type and class desired as well as for
 * processing the question section of the response packets.
 */
struct dns_query_t {
    uint16_t type;
    uint16_t class;
};



/*
 * NSID option information to go in the RDATA field of a resource record.
 * Used in the query to request an NSID response.
 */
struct dns_opt_rdata_t {
    uint16_t code;
    uint16_t length;
};

/* pseudo OPT RR header includes a one byte zero length name at the start */
#define SIZEOF_PSEUDO_RR (sizeof(struct dns_opt_rr_t) + sizeof(uint8_t))



/*
 * Information block recording data for each DNS request test packet 
 * that is sent, and when the response is received.
 */
struct info_t {
    char response[MAX_DNS_NAME_LEN];	/* the raw query response */
    struct addrinfo *addr;		/* address probe was sent to */
    struct timeval time_sent;		/* when the probe was sent */
    uint32_t delay;			/* delay in receiving response, usec */
    uint32_t query_length;		/* number of bytes in query */
    uint32_t bytes;			/* number of bytes in response */
    //uint16_t receive_flags;		/* flags set by responding server */
    union flags_t flags;
    uint16_t total_answer;
    uint16_t total_authority;
    uint16_t total_additional;
    uint8_t reply;			/* set to 1 once we have a reply */ 
    uint8_t response_code;
    uint8_t dnssec_response;
    uint8_t addr_count;
    uint8_t ttl;
};



/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    char *query_string;
    uint16_t query_type;
    uint16_t query_class;
    uint16_t udp_payload_size;
    int recurse;
    int dnssec;
    int nsid;
    int perturbate;
};



struct dns_report_item_t {
    /* nicer way than storing just 16 bytes for the address? */
    char address[16];
    int32_t rtt;
    uint32_t query_length;		/* number of bytes in query */
    uint32_t response_size;
    uint16_t total_answer;
    uint16_t total_authority;
    uint16_t total_additional;
    union flags_t flags;
    uint8_t family;
    uint8_t ttl;
    uint8_t namelen;
    uint8_t instancelen;
} __attribute__((__packed__));

struct dns_report_header_t {
    uint32_t version;
    uint16_t query_type;
    uint16_t query_class;
    uint16_t udp_payload_size;
    uint8_t recurse:1;
    uint8_t dnssec:1;
    uint8_t nsid:1;
    uint8_t reserved:5;
    uint8_t count;
    uint8_t querylen;
} __attribute__((__packed__));

#endif
