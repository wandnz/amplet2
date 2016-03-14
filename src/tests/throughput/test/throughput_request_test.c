#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "throughput.h"
#include "serverlib.h"

/*
 * Check that the throughput test request messages are sensible.
 */
int main(void) {
    int pipefd[2];
    struct ctrlstream sendctrl, recvctrl;
    /* type bytes duration write_size X X X X X X */
    struct test_request_t *request;
    struct test_request_t requests[] = {
        { TPUT_PKT_SEND, 0, 0, 0, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 1024, 0, 128, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 10*1024*1024, 0, 1024, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 0, 10, 4096, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 0, 60, 4096, 0,0,0,0,0,0 },
        { TPUT_PKT_SEND, 0, 300, 12345, 0,0,0,0,0,0 },
    };
    void *data;
    int bytes;
    int count;
    int i;

    count = sizeof(requests) / sizeof(struct test_request_t);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    sendctrl.type = recvctrl.type = PLAIN_CONTROL_STREAM;
    sendctrl.stream.sock = pipefd[1];
    recvctrl.stream.sock = pipefd[0];

    /* try sending each of the test option sets */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        if ( send_control_send(AMP_TEST_THROUGHPUT, &sendctrl,
                    build_send(&requests[i])) < 0 ) {
            return -1;
        }

        /* read it out the other end... */
        if ( (bytes=read_control_packet(&recvctrl, &data)) < 0 ) {
            return -1;
        }

        /* ... and make sure it matches what we sent */
        if ( parse_control_send(AMP_TEST_THROUGHPUT, data, bytes,
                    (void**)&request, parse_send) < 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(requests[i].bytes == request->bytes);
        assert(requests[i].duration == request->duration);
        assert(requests[i].write_size == request->write_size);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
