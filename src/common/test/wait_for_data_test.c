#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "testlib.h"

#define TEST_PACKETS 1000
#define MAX_PACKET_LEN 512

/*
 * Check that the correct sockets are reported as having data available when
 * waiting for data on either an ipv4 or ipv6 socket.
 */
int main(void) {
    int sockets[2];
    struct socket_t amp_sockets;
    char out_packet[MAX_PACKET_LEN];
    char in_packet[MAX_PACKET_LEN];
    int maxwait, length, i;
    int sock = -1;

    /*
     * use a pair of unix sockets to test sending data without relying on
     * the network being present/sane/etc.
     */
    if ( socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0 ) {
        fprintf(stderr, "Failed to create socket pair: %s\n", strerror(errno));
        return -1;
    }

    /*
     * The code under test doesn't actually care about the address family
     * and will assume that "socket" is ipv4 and "socket6" is ipv6.
     */
    amp_sockets.socket = sockets[0];
    amp_sockets.socket6 = sockets[1];

    for ( i = 0; i < TEST_PACKETS; i++ ) {
        /* fill the packet with some data we can check later */
        length = i % MAX_PACKET_LEN;
        out_packet[length++] = i % 255;
        maxwait = 1;

        switch ( i % 3 ) {
            case 0:
                /* send to the ipv4 socket, to trigger ipv6 as ready to read */
                send(amp_sockets.socket, out_packet, length, 0);
                assert(wait_for_data(&amp_sockets, &maxwait) == AF_INET6);
                sock = amp_sockets.socket6;
                break;
            case 1:
                /* send to the ipv6 socket, to trigger ipv4 as ready to read */
                send(amp_sockets.socket6, out_packet, length, 0);
                assert(wait_for_data(&amp_sockets, &maxwait) == AF_INET);
                sock = amp_sockets.socket;
                break;
            case 2:
                /* no data has been written, it should timeout */
                assert(wait_for_data(&amp_sockets, &maxwait) == -1);
                sock = -1;
                break;
        };

        if ( sock > 0 ) {
            /* read out what was just written so there is no data ready */
            recv(sock, in_packet, MAX_PACKET_LEN, 0);

            /* confirm that it matches what we sent */
            assert(memcmp(out_packet, in_packet, length) == 0);
        }
    }

    close(sockets[0]);
    close(sockets[1]);

    return 0;
}
