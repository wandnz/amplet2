#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "throughput.h"

/*
 * Check that the throughput test request messages are sensible.
 */
int main(void) {
    int pipefd[2];
    struct packet_t packet;
    int bytes_read, bytes_written;
    /* type bytes duration write_size X X X X X X */
    struct test_request_t requests[] = {
        { TPUT_PKT_SEND, 0, 0, 0, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 1024, 0, 128, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 10*1024*1024, 0, 1024, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 0, 10, 4096, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 0, 60, 4096, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 0, 300, 12345, 0,0,0,0,0,0 },
    };
    int count;
    int i;

    count = sizeof(requests) / sizeof(struct test_request_t);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    /* try sending each of the test option sets */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        bytes_written = sendRequestTestPacket(pipefd[1], &requests[i]);
        assert(bytes_written == sizeof(struct packet_t));

        /* read it out the other and make sure it matches what we sent */
        memset(&packet, 0, sizeof(packet));
        bytes_read = readPacket(pipefd[0], &packet, NULL);

        assert(bytes_read == sizeof(struct packet_t));
        assert(bytes_written == bytes_read);

        /* check everything we received matches what we sent */
        assert(packet.header.type == TPUT_PKT_SEND);
        assert(requests[i].bytes == packet.types.send.bytes);
        assert(requests[i].duration == packet.types.send.duration_ms);
        assert(requests[i].write_size == packet.types.send.write_size);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
