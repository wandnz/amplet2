#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "throughput.h"
#include "serverlib.h"
#include "controlmsg.h"

/*
 * Check that the throughput test hello messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
    /* X tport X mss nagle rand web10g X rcv snd X X X X X */
    struct opt_t optionsA[] = {
        { 0, 12345, 0, 1460, 0, 0, 1, 0, 0, 0, 0,0,0,0,0},
        { 0, 1, 0, 536, 0, 1, 0, 0, 4096, 0, 0,0,0,0,0},
        { 0, DEFAULT_CONTROL_PORT, 0, 1220, 0, 1, 1, 0, 0, 4096, 0,0,0,0,0},
        { 0, DEFAULT_TEST_PORT, 0, 5960, 1, 0, 0, 0, 4096, 4096, 0, 0, 0, 0, 0},
        { 0, 65535, 0, 8960, 1, 1, 1, 0, 1234, 5678, 0, 0, 0, 0, 0},
        { 0, 65535, 0, 8960, 0, 0, 0, 0, 98765, 54321, 0, 0, 0, 0, 0},
    };
    struct opt_t *optionsB;
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
        if ( send_control_hello(AMP_TEST_THROUGHPUT, sendctrl,
                    build_hello(&optionsA[i])) < 0 ) {
            return -1;
        }

        /* read it out the other and make sure it matches what we sent */
        if ( read_control_hello(AMP_TEST_THROUGHPUT, recvctrl,
                    (void**)&optionsB, parse_hello) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(optionsA[i].sock_disable_nagle == optionsB->sock_disable_nagle);
        assert(optionsA[i].disable_web10g == optionsB->disable_web10g);
        assert(optionsA[i].randomise == optionsB->randomise);
        assert(optionsA[i].tport == optionsB->tport);
        assert(optionsA[i].sock_mss == optionsB->sock_mss);
        assert(optionsA[i].sock_rcvbuf == optionsB->sock_rcvbuf);
        assert(optionsA[i].sock_sndbuf == optionsB->sock_sndbuf);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
