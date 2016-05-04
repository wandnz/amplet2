#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "udpstream.h"
#include "controlmsg.h"

/*
 * Check that the udpstream test request messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
    struct opt_t optionsA[] = {
        { 0, 1, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 100, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 1024, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 1025, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 8816, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 8817, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 8826, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 8827, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 12345, 0, 0, 0, 0, 0, 0, 0 },
        { 0, 65535, 0, 0, 0, 0, 0, 0, 0 },
    };
    struct opt_t *optionsB;
    void *data;
    int bytes;
    int count;
    int i;

    count = sizeof(optionsA) / sizeof(struct opt_t);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    sendctrl = BIO_new_socket(pipefd[1], BIO_CLOSE);
    recvctrl = BIO_new_socket(pipefd[0], BIO_CLOSE);

    /* try sending each of the test option sets */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        if ( send_control_send(AMP_TEST_UDPSTREAM, sendctrl,
                    build_send(&optionsA[i])) < 0 ) {
            return -1;
        }

        /* read it out the other end... */
        if ( (bytes=read_control_packet(recvctrl, &data)) < 0 ) {
            return -1;
        }

        /* ... and make sure it matches what we sent */
        if ( parse_control_send(AMP_TEST_UDPSTREAM, data, bytes,
                    (void**)&optionsB, parse_send) < 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(optionsA[i].tport == optionsB->tport);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
