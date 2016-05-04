#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "throughput.h"
#include "throughput.pb-c.h"


/* these are globals as we need to get them into the print callback */
struct test_request_t *info;
struct opt_t options;
unsigned int count;
struct addrinfo *addr;



/*
 *
 */
static void free_info(void) {
    struct test_request_t *tmp;
    assert(info);

    while ( info != NULL ) {
        tmp = info;
        info = info->next;

        if ( tmp->s_result ) {
            free(tmp->s_result);
            tmp->s_result = NULL;
        }
        if ( tmp->c_result ) {
            free(tmp->c_result);
            tmp->c_result = NULL;
        }

        free(tmp);
    }
}



/*
 *
 */
static struct test_request_t* build_info(struct test_request_t *next,
        enum tput_type direction, uint64_t start, uint64_t end,
        uint64_t bytes) {

    struct test_request_t *item;
    struct test_result_t *result;

    item = (struct test_request_t*)malloc(sizeof(struct test_request_t)*count);
    item->type = direction;
    item->next = next;
    item->s_web10g = NULL;
    item->c_web10g = NULL;

    result = (struct test_result_t*)malloc(sizeof(struct test_result_t));
    result->start_ns = start * 1000000000;
    result->end_ns = end * 1000000000;
    result->bytes = bytes;

    if ( item->type == TPUT_2_CLIENT ) {
        item->c_result = result;
        item->s_result = malloc(sizeof(struct test_result_t));
    } else {
        item->s_result = result;
        item->c_result = malloc(sizeof(struct test_result_t));
    }

    return item;
}



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Throughput__Header *b) {
    assert(b->has_write_size);
    assert(a->write_size == b->write_size);
    assert(strcmp(a->textual_schedule, b->schedule) == 0);
}



/*
 * Check that the address in the result item matches the address that the
 * test tried to report.
 */
static void verify_address(struct addrinfo *a, Amplet2__Throughput__Header *b) {
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
static void verify_response(struct test_request_t *a,
        Amplet2__Throughput__Item *b) {

    struct test_result_t *result;

    assert(b->has_direction);
    assert((int)a->type == (int)b->direction);

    result = (a->type == TPUT_2_CLIENT) ? a->c_result : a->s_result;

    assert(b->has_duration);
    assert(result->end_ns - result->start_ns == b->duration);
    assert(b->has_bytes);
    assert(result->bytes == b->bytes);
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Throughput__Report *msg;
    struct test_request_t *tmpinfo;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__throughput__report__unpack(NULL, result->len, result->data);
    tmpinfo = info;

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == count);

    verify_header(&options, msg->header);
    verify_address(addr, msg->header);//XXX

    /* check each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        verify_response(tmpinfo, msg->reports[i]);
        /* advance to the next set of test results */
        tmpinfo = tmpinfo->next;
    }

    amplet2__throughput__report__free_unpacked(msg, NULL);
}



/*
 *
 */
int main(void) {
    addr = get_numeric_address("192.168.0.254", NULL);
    addr->ai_canonname = strdup("foo.bar.baz");

    count = 26;

    /* direction, start, end, bytes */
    info = build_info(NULL, TPUT_2_CLIENT, 0, 1000, 12345);
    info = build_info(info, TPUT_2_SERVER, 0, 0, 0);
    info = build_info(info, TPUT_2_CLIENT, 0, 0, 1);
    info = build_info(info, TPUT_2_SERVER, 1, 1, 0);
    info = build_info(info, TPUT_2_CLIENT, 1, 1, 1);
    info = build_info(info, TPUT_2_SERVER, 1, 2, 1);
    /* around the current time and date */
    info = build_info(info, TPUT_2_CLIENT, 1439265634, 1439265634, 256);
    info = build_info(info, TPUT_2_SERVER, 1439265634, 1439265664, 65536);
    /* around 2^16 */
    info = build_info(info, TPUT_2_CLIENT, 65536, 65536, 65536);
    info = build_info(info, TPUT_2_SERVER, 65536, 65537, 65537);
    info = build_info(info, TPUT_2_SERVER, 65535, 65597, 65535);
    /* around 2^31 */
    info = build_info(info, TPUT_2_CLIENT, 2147483648, 2147483648, 2147483648);
    info = build_info(info, TPUT_2_SERVER, 2147483648, 2147483649, 2147483649);
    info = build_info(info, TPUT_2_SERVER, 2147483647, 2147483699, 2147483647);
    /* around 2^32 */
    info = build_info(info, TPUT_2_CLIENT, 4294967296, 4294967296, 4294967296);
    info = build_info(info, TPUT_2_SERVER, 4294967296, 4294967297, 4294967297);
    info = build_info(info, TPUT_2_SERVER, 4294967295, 4294967397, 4294967295);
    /* around 2^33 */
    info = build_info(info, TPUT_2_CLIENT, 8589934592, 8589934592, 8589934592);
    info = build_info(info, TPUT_2_SERVER, 8589934592, 8589934593, 8589934593);
    info = build_info(info, TPUT_2_SERVER, 8589934591, 8589934793, 8589934592);
    /* around 2^34 */
    info = build_info(info, TPUT_2_CLIENT, 17179869184, 17179869184,
            17179869184);
    info = build_info(info, TPUT_2_SERVER, 17179869184, 17179869185,
            17179869185);
    info = build_info(info, TPUT_2_SERVER, 17179869183, 17179869884,
            17179869183);
    /* around max value (2^64 / 1000000000 because times are in nanoseconds)) */
    info = build_info(info, TPUT_2_CLIENT, 18446744073, 18446744073,
            18446744073);
    info = build_info(info, TPUT_2_SERVER, 18446744072, 18446744073,
            9223372036854775808U);
    info = build_info(info, TPUT_2_SERVER, 9223372036U, 18446744073,
            18446744073709551615U);

    options.schedule = info;

    /*
     * try some different combinations of header options, they don't need to
     * relate to the results reported (but maybe that should be enforced?)
     */
    options.write_size = 0;
    options.textual_schedule = "s1000,r,S2000";
    verify_message(amp_test_report_results(0, addr, &options));

    options.write_size = 84;
    options.textual_schedule = "t1000,r,T2000";
    verify_message(amp_test_report_results(0, addr, &options));

    options.write_size = DEFAULT_WRITE_SIZE;
    options.textual_schedule = "s0,s4294967296";
    verify_message(amp_test_report_results(0, addr, &options));

    options.write_size = 4294967295U;
    options.textual_schedule = "s4294967296,s4294967296";
    verify_message(amp_test_report_results(0, addr, &options));

    free_info();
    free(info);
    freeaddrinfo(addr);
    return 0;
}
