#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "testlib.h"
#include "global.h" /* required just for inter packet delay */

#define TEST_PACKETS 10000
#define MAX_PACKET_LEN 512


/*
 * Check that packets are being sent correctly and that the delay between
 * sending them is being enforced properly.
 *
 * To do that we are just doing an average speed check - send all the packets
 * and make sure that it takes at least as long as the number of packets
 * multiplied by the minimum inter-packet wait time. If the machine is heavily
 * loaded then this check becomes less useful, but I think it's still
 * worthwhile.
 */
int main(void) {
    struct addrinfo dest;
    int sockets[2];
    char out_packet[MAX_PACKET_LEN];
    char in_packet[MAX_PACKET_LEN];
    int delay, result, length, i;
    struct timeval start, end;
    uint64_t duration;

    /*
     * use a pair of unix sockets to test sending data without relying on
     * the network being present/sane/etc.
     */
    if ( socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0 ) {
        fprintf(stderr, "Failed to create socket pair: %s\n", strerror(errno));
        return -1;
    }

    /* we don't need a real address for testing, our socket pair is connected */
    dest.ai_addr = NULL;
    dest.ai_addrlen = 0;

    gettimeofday(&start, NULL);

    for ( i = 0; i < TEST_PACKETS; i++ ) {
        /* fill the packet with some data we can check later */
        length = i % MAX_PACKET_LEN;
        out_packet[length++] = i % 255;

        /* loop until the packet is allowed to be sent or errors */
        while ( (delay = delay_send_packet(sockets[0], out_packet, length,
                        &dest, MIN_INTER_PACKET_DELAY, NULL)) > 0 ) {
            assert(delay < MIN_INTER_PACKET_DELAY);
            usleep(delay);
        }

        if ( delay < 0 ) {
            fprintf(stderr, "Failed to send packet: %s\n", strerror(errno));
            return -1;
        }

        /* try to read the packet that we just sent */
        if ( (result = recv(sockets[1], in_packet, MAX_PACKET_LEN, 0)) !=
                length ) {
            fprintf(stderr, "Failed to receive packet: %s\n", strerror(errno));
            return -1;
        }

        /* confirm that it matches what we sent */
        assert(memcmp(out_packet, in_packet, length) == 0);
    }

    gettimeofday(&end, NULL);

    /* check that we took longer than the minimum possible time */
    duration = DIFF_TV_US(end, start);
    assert(duration > (TEST_PACKETS * MIN_INTER_PACKET_DELAY));

    close(sockets[0]);
    close(sockets[1]);

    return 0;
}
