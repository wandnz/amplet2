#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "throughput.h"
#include "controlmsg.h"

/*
 * Check that the throughput test ready messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
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

    sendctrl = BIO_new_socket(pipefd[1], BIO_CLOSE);
    recvctrl = BIO_new_socket(pipefd[0], BIO_CLOSE);

    /* try sending each of the test ports */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        if ( send_control_ready(AMP_TEST_THROUGHPUT, sendctrl,ports[i]) < 0 ) {
            return -1;
        }

        /* read it out the other and make sure it matches what we sent */
        if ( read_control_ready(AMP_TEST_THROUGHPUT, recvctrl, &tport) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(ports[i] == tport);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
