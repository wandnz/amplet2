#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "throughput.h"

/*
 * Check that the throughput test ready messages are sensible.
 */
int main(void) {
    int pipefd[2];
    struct packet_t packet;
    int bytes_read, bytes_written;
    uint16_t ports[] = {
        1, 100, 1024, 1025, 8816, 8817, 8826, 8827, 12345, 65535
    };
    uint16_t tport;
    int count;
    int i;

    count = sizeof(ports) / sizeof(int);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    /* try sending each of the test ports */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        bytes_written = sendReadyPacket(pipefd[1], ports[i]);
        assert(bytes_written == sizeof(struct packet_t));

        /* read it out the other and make sure it matches what we sent */
        memset(&packet, 0, sizeof(packet));
        bytes_read = readPacket(pipefd[0], &packet, NULL);

        assert(bytes_read == sizeof(struct packet_t));
        assert(bytes_written == bytes_read);

        /* parse the ready packet */
        if ( readReadyPacket(&packet, &tport) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(packet.header.type == TPUT_PKT_READY);
        assert(ports[i] == tport);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
