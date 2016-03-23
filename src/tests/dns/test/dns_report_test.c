#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "dns.h"
#include "dns.pb-c.h"


/* these are globals as we need to get them into the print callback */
struct info_t *info;
unsigned int count;
struct opt_t *options;



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Dns__Header *b) {
    assert(b->has_query_type);
    assert(b->has_query_class);
    assert(b->has_udp_payload_size);
    assert(b->has_recurse);
    assert(b->has_dnssec);
    assert(b->has_nsid);
    assert(b->query != NULL);

    assert(a->query_type == b->query_type);
    assert(a->query_class == b->query_class);
    assert(a->udp_payload_size == b->udp_payload_size);
    assert(a->recurse == b->recurse);
    assert(a->dnssec == b->dnssec);
    assert(a->nsid == b->nsid);
    assert(strcmp(a->query_string, b->query) == 0);
}



/*
 * Check that the address in the result item matches the address that the
 * test tried to report.
 */
static void verify_address(struct addrinfo *a, Amplet2__Dns__Item *b) {
    assert(b->has_family);
    assert(b->has_address);

    /* ensure family matches */
    assert(a->ai_family == b->family);

    /* ensure address length and address match */
    switch ( a->ai_family ) {
        case AF_INET:
            assert(b->address.len == sizeof(struct in_addr));
            assert(memcmp(b->address.data,
                        &((struct sockaddr_in*)a->ai_addr)->sin_addr,
                        sizeof(struct in_addr)) == 0);
            break;

        case AF_INET6:
            assert(b->address.len == sizeof(struct in6_addr));
            assert(memcmp(b->address.data,
                        &((struct sockaddr_in6*)a->ai_addr)->sin6_addr,
                        sizeof(struct in6_addr)) == 0);
            break;

        default: assert(0);
    };

    /* ensure the target names match */
    assert(strcmp(b->name, a->ai_canonname) == 0);
}



/*
 * Check that the RTT/TTL are present or not and have the correct values,
 * based on the same logic used when reporting.
 */
static void verify_response(struct info_t *a, Amplet2__Dns__Item *b) {
    assert(b->has_query_length);
    assert(a->query_length == b->query_length);

    /* ensure rtt, flags etc are only set if there was a valid response */
    if ( a->reply && a->time_sent.tv_sec > 0 ) {
        assert(b->has_rtt);
        assert(a->delay == b->rtt);
        assert(b->has_ttl);
        assert(a->ttl == b->ttl);
        assert(b->has_response_size);
        assert(a->bytes == b->response_size);
        assert(b->has_total_answer);
        assert(a->total_answer == b->total_answer);
        assert(b->has_total_authority);
        assert(a->total_authority == b->total_authority);
        assert(b->has_total_additional);
        assert(a->total_additional == b->total_additional);
        /* flags */
        assert(b->flags);
        assert(b->flags->has_qr);
        assert(a->flags.fields.qr == b->flags->qr);
        assert(b->flags->has_opcode);
        assert(a->flags.fields.opcode == b->flags->opcode);
        assert(b->flags->has_aa);
        assert(a->flags.fields.aa == b->flags->aa);
        assert(b->flags->has_tc);
        assert(a->flags.fields.tc == b->flags->tc);
        assert(b->flags->has_rd);
        assert(a->flags.fields.rd == b->flags->rd);
        assert(b->flags->has_ra);
        assert(a->flags.fields.ra == b->flags->ra);
        assert(b->flags->has_z);
        assert(a->flags.fields.z == b->flags->z);
        assert(b->flags->has_ad);
        assert(a->flags.fields.ad == b->flags->ad);
        assert(b->flags->has_cd);
        assert(a->flags.fields.cd == b->flags->cd);
        assert(b->flags->has_rcode);
        assert(a->flags.fields.rcode == b->flags->rcode);

        /* possible instance name from NSID OPT RR */
        if ( strlen(a->response) > 0 ) {
            assert(b->instance != NULL);
            assert(strcmp(a->response, b->instance) == 0);
        } else {
            assert(b->instance == NULL);
        }
    } else {
        assert(!b->has_rtt);
        assert(!b->has_ttl);
        assert(!b->has_response_size);
        assert(!b->has_total_answer);
        assert(!b->has_total_authority);
        assert(!b->has_total_additional);
        /* flags */
        assert(b->flags == NULL);
        assert(b->instance == NULL);
    }
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Dns__Report *msg;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__dns__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == count);

    verify_header(options, msg->header);

    /* check each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        verify_address(info[i].addr, msg->reports[i]);
        verify_response(&info[i], msg->reports[i]);
    }

    amplet2__dns__report__free_unpacked(msg, NULL);
}



/*
 *
 */
static void build_info(struct info_t *item, struct addrinfo *addr,
    uint32_t query_length, uint32_t bytes, uint32_t delay, uint8_t reply,
    uint8_t ttl, uint16_t total_answer, uint16_t total_authority,
    uint16_t total_additional, uint8_t dnssec_response, uint16_t flags,
    char *response, uint32_t seconds) {

    item->addr = addr;
    item->query_length = query_length;
    item->bytes = bytes;
    item->delay = delay;
    item->reply = reply;
    item->ttl = ttl;
    item->total_answer = total_answer;
    item->total_authority = total_authority;
    item->total_additional = total_additional;
    item->dnssec_response = dnssec_response;
    item->flags.bytes = flags;
    if ( response != NULL ) {
        strcpy(item->response, response);
    } else {
        memset(item->response, 0, sizeof(item->response));
    }
    item->time_sent.tv_sec = seconds;
    item->time_sent.tv_usec = 0;
}



/*
 *
 */
int main(void) {
    unsigned int i;
    test_t dns_test;
    struct timeval start_time;
    struct addrinfo *addr = get_numeric_address("192.168.0.254", NULL);
    struct opt_t full_options[] = {
        /* query, type, class, size, recurse, dnssec, nsid, pert, inter, dscp */
        {"www.example.com", 0x0, 0x0, 0, 0, 0, 0, 0, 0, 0},
        {"www.example.com", 0x1, 0x1, 512, 0, 0, 0, 1, 0, 8},
        {"www.example.com", 0x1c, 0x1, 1280, 0, 0, 1, 0, 0, 10},
        {"www.example.com", 0xff, 0xff, 4096, 0, 0, 1, 1, 0, 12},
        {"www.example.com", 0x8001, 0xffff, 8192, 0, 1, 0, 0, 0, 16},

        {"www.example.org", 0x0, 0x0, 0, 0, 1, 0, 1, 0, 20},
        {"www.example.org", 0x1, 0x1, 511, 0, 1, 1, 0, 0, 24},
        {"www.example.org", 0x1c, 0x1, 1279, 0, 1, 1, 1, 0, 26},
        {"www.example.org", 0xff, 0xff, 4095, 1, 0, 0, 0, 0, 28},
        {"www.example.org", 0x8001, 0xffff, 8191, 1, 0, 0, 1, 0, 30},

        {"example.com", 0x0, 0x1, 0, 1, 0, 1, 0, 0, 34},
        {"example.com", 0x1, 0x1, 513, 1, 0, 1, 1, 0, 36},
        {"example.com", 0x1c, 0x1, 1281, 1, 1, 0, 0, 0, 46},
        {"example.com", 0xff, 0xff, 4097, 1, 1, 0, 1, 0, 48},
        {"example.com", 0x8001, 0xffff, 8193, 1, 1, 1, 0, 0, 56},

        {"www.example.com", 0xffff, 0x1, 8192, 1, 1, 1, 1, 0, 63},
    };

    addr->ai_canonname = strdup("foo.bar.baz");

    /* replace the print function with one that will verify message contents */
    dns_test.print_callback = verify_message;
    /* use this stripped down test in place of the normal DNS test */
    amp_tests[AMP_TEST_DNS] = &dns_test;

    /* build some different sets of result structures */
    count = 20;
    info = (struct info_t*)malloc(sizeof(struct info_t) * count);

    /* txlen, rxlen, rtt, reply, ttl, t1, t2, t3, dnssec, flags, instance, s */

    /* no reply, no start time */
    build_info(&info[0], addr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0, NULL, 0);
    build_info(&info[1], addr, 10, 20, 100, 0, 1, 2, 3, 4, 0, 0xff, NULL, 0);
    build_info(&info[2], addr, 10, 20, 123, 0, 1, 2, 3, 4, 1, 0xff, "foo", 0);
    build_info(&info[3], addr, 10, 20, 10000, 0, 1, 2, 3, 4, 1, 0xff, "bar", 0);
    build_info(&info[4], addr, 0xffff, 0xffff, 0xffff, 0, 0xff, 0xffff,
            0xffff, 0xffff, 1, 0xffff, "foo.bar.baz", 0);

    /* no reply, start time */
    build_info(&info[5], addr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0, NULL, 1);
    build_info(&info[6], addr, 10, 20, 100, 0, 1, 2, 3, 4, 0, 0xff, NULL, 1);
    build_info(&info[7], addr, 10, 20, 123, 0, 1, 2, 3, 4, 1, 0xff, "foo", 1);
    build_info(&info[8], addr, 10, 20, 10000, 0, 1, 2, 3, 4, 1, 0xff, "bar", 1);
    build_info(&info[9], addr, 0xffff, 0xffff, 0xffff, 0, 0xff, 0xffff,
            0xffff, 0xffff, 1, 0xffff, "foo.bar.baz", 1);

    /* reply, no start time */
    build_info(&info[10], addr, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0x0, NULL, 0);
    build_info(&info[11], addr, 10, 20, 100, 1, 1, 2, 3, 4, 0, 0xff, NULL, 0);
    build_info(&info[12], addr, 10, 20, 123, 1, 1, 2, 3, 4, 1, 0xff, "foo", 0);
    build_info(&info[13], addr, 10, 20, 1000, 1, 1, 2, 3, 4, 1, 0xff, "bar", 0);
    build_info(&info[14], addr, 0xffff, 0xffff, 0xffff, 1, 0xff, 0xffff,
            0xffff, 0xffff, 1, 0xffff, "foo.bar.baz", 0);

    /* reply and start time */
    build_info(&info[15], addr, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0x0, NULL, 1);
    build_info(&info[16], addr, 10, 20, 100, 1, 1, 2, 3, 4, 0, 0xff, NULL, 1);
    build_info(&info[17], addr, 10, 20, 123, 1, 1, 2, 3, 4, 1, 0xff, "foo", 1);
    build_info(&info[18], addr, 10, 20, 1000, 1, 1, 2, 3, 4, 1, 0xff, "bar", 1);
    build_info(&info[19], addr, 0xffff, 0xffff, 0xffff, 1, 0xff, 0xffff,
            0xffff, 0xffff, 1, 0xffff, "foo.bar.baz", 1);

    build_info(&info[15], addr, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0x0, NULL, 1);
    build_info(&info[16], addr, 10, 20, 100, 1, 1, 2, 3, 4, 0, 0xff, NULL, 1);
    build_info(&info[17], addr, 100, 200, 123, 1, 1, 2, 3, 4, 1, 0xff, "foo",1);
    build_info(&info[18], addr, 1000, 20000, 10000, 1, 1, 2, 3, 4, 1, 0xff,
            "bar", 1);
    build_info(&info[19], addr, 0xffff, 0xffff, 0xffff, 1, 0xff, 0xffff,
            0xffff, 0xffff, 1, 0xffff, "foo.bar.baz", 1);

    /* check these results with a series of different test options */
    for ( i = 0; i < sizeof(full_options) / sizeof(struct opt_t); i++ ) {
        options = &full_options[i];
        amp_test_report_results(&start_time, count, info, options);
    }

    free(info);
    freeaddrinfo(addr);
    return 0;
}
