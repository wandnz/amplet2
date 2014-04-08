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
 * Check that data is received correctly by get_packet() and that the correct
 * amount of data is received, on both ipv4 and ipv6 code paths.
 */
int main(void) {
    int sockets[2];
    struct socket_t amp_sockets;
    char out_packet[MAX_PACKET_LEN];
    char in_packet[MAX_PACKET_LEN];
    int maxwait, length, bytes, i;
    struct sockaddr_storage saddr;
    int sent = -1;

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
                sent = send(amp_sockets.socket, out_packet, length, 0);
                break;
            case 1:
                /* send to the ipv6 socket, to trigger ipv4 as ready to read */
                sent = send(amp_sockets.socket6, out_packet, length, 0);
                break;
            case 2:
                /* no data has been written, it should timeout */
                sent = 0;
                break;
        };

        /*
         * There might be some sizing issues with get_packet() setting addrlen
         * internally to the sizeof a sockaddr_in or sockaddr_in6, but that\
         * will just truncate the address returned by recvfrom(), something we
         * aren't looking at.
         */
        bytes = get_packet(&amp_sockets, in_packet, MAX_PACKET_LEN,
                (struct sockaddr*)&saddr, &maxwait);

        assert(bytes == sent);

        if ( bytes > 0 ) {
            /* confirm that it matches what we sent */
            assert(memcmp(out_packet, in_packet, bytes) == 0);
        }
    }

    close(sockets[0]);
    close(sockets[1]);

    return 0;
}
