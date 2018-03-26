#ifndef _TESTS_YOUTUBE_H
#define _TESTS_YOUTUBE_H

#include <stdint.h>
#include "tests.h"
#include "youtube.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif
void *cpp_main(int argc, const char *argv[]);
amp_test_result_t* run_youtube(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_youtube(amp_test_result_t *result);
test_t *register_test(void);

#ifdef __cplusplus
}
#endif

struct opt_t {
    char *video;
    char *quality;
    int forcev4;                                /* force use of ipv4 */
    int forcev6;                                /* force use of ipv6 */
    char *device;                               /* source device name */
    char *sourcev4;                             /* source v4 address */
    char *sourcev6;                             /* source v6 address */
    long sslversion;                            /* SSL version to use */
    uint8_t dscp;
};

struct TimelineEvent {
    uint64_t timestamp;
    Amplet2__Youtube__EventType type;
    Amplet2__Youtube__Quality quality;
    struct TimelineEvent *next;
};

struct YoutubeTiming {
    char *video;
    char *title;
    Amplet2__Youtube__Quality quality;
    uint64_t initial_buffering;
    uint64_t playing_time;
    uint64_t stall_time;
    uint64_t stall_count;
    uint64_t total_time;
    uint64_t pre_time;
    uint64_t reported_duration;
    uint64_t event_count;
    struct TimelineEvent *timeline;
};


#if UNIT_TEST
/*
int amp_test_process_ipv4_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now);
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt);
*/
#endif

#endif
