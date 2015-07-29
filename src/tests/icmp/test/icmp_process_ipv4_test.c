#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <time.h>

#include "tests.h"
#include "icmp.h"

#define MAX_PACKET_LEN 512
#define MIN_VALID_LEN ( \
        sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(uint16_t) )
#define MIN_EMBEDDED_LEN ( \
        (2*sizeof(struct iphdr)) + (2*sizeof(struct icmphdr)) )

/*
 */
int main(void) {
    char packet[MAX_PACKET_LEN];
    int count;
    struct info_t *info;
    struct timeval now = {0, 0};
    struct iphdr *ip;
    int i;
    struct icmphdr icmps[] = {
        /* good response */
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(1), 0}} },
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(123), htons(1)}} },
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(5678), htons(2)}} },

        /* good response, but too short */
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(5678), htons(3)}} },
        { ICMP_ECHOREPLY, 0, 0, { .echo = {htons(5678), htons(4)}} },

        /* incorrect responses */
        { ICMP_ECHO, 0, 0, { .echo = {htons(5678), htons(5)}} },
        { NR_ICMP_TYPES+1, 0, 0, { .echo = {htons(5678), htons(6)}} },

        /* TODO incorrect responses with embedded packets */
        //{ ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0, { .echo = {0, 0} } },
    };
    unsigned int length[] = {
        /* good response responses */
        MIN_VALID_LEN,
        MIN_VALID_LEN,
        MIN_VALID_LEN,

        /* good response, but too short */
        sizeof(struct iphdr) + sizeof(struct icmphdr),
        sizeof(struct iphdr),

        /* incorrect responses */
        MIN_VALID_LEN,
        MIN_VALID_LEN,

        /* TODO incorrect responses with embedded packets */
        //MIN_EMBEDDED_LEN,
    };
    int results[] = { 0, 0, 0, -1, -1, -1, -1, /*0*/ };

    /* check our test settings and results match up */
    assert((sizeof(icmps) / sizeof(struct icmphdr)) ==
            (sizeof(results) / sizeof(int)));
    assert(sizeof(icmps) / sizeof(struct icmphdr) ==
            (sizeof(length) / sizeof(int)));

    count = sizeof(icmps) / sizeof(struct icmphdr);

    info = (struct info_t *)malloc(sizeof(struct info_t) * count);
    memset(info, 0, sizeof(struct info_t) * count);
    memset(packet, 0, sizeof(packet));

    /* TODO change the IP header length in some tests? */
    ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;

    srand(time(NULL));

    for ( i = 0; i < count; i++ ) {
        info[i].magic = rand();
        ip->tot_len = length[i];

        /* fill the packet with each icmp header and magic in turn */
        memcpy(packet + sizeof(struct iphdr),&icmps[i],sizeof(struct icmphdr));
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr),
                &info[i].magic, sizeof(info[i].magic));

        /* check that it passed or failed appropriately */
        assert(amp_test_process_ipv4_packet(packet, length[i],
                    ntohs(icmps[i].un.echo.id), now, i, info) == results[i]);

        /*
         * The error type/code will only be set if it can be determined to be a
         * response to a probe packet that we sent. If it's too short or too
         * wrong, then this won't be set.
         */
        if ( icmps[i].type < NR_ICMP_TYPES && icmps[i].type != ICMP_ECHO &&
                length[i] >= MIN_VALID_LEN ) {
            assert(info[i].err_type == icmps[i].type);
            assert(info[i].err_code == icmps[i].code);
        }
    }

    return 0;
}
