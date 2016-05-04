#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "udpstream.h"
#include "serverlib.h"
#include "controlmsg.h"

/*
 * Check that the throughput test hello messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
    /* X tport size count spacing pcnt samples dscp X */
    struct opt_t optionsA[] = {
        {0, 12345, 0, 0, 0, 0, 0, 0, 0},

        {0, 1, MINIMUM_UDPSTREAM_PACKET_LENGTH,
            MINIMUM_UDPSTREAM_PACKET_COUNT, MIN_INTER_PACKET_DELAY,
            4, 2, 0x20, 0},

        {0, DEFAULT_CONTROL_PORT, DEFAULT_UDPSTREAM_PACKET_LENGTH,
            DEFAULT_UDPSTREAM_PACKET_COUNT,DEFAULT_UDPSTREAM_INTER_PACKET_DELAY,
            DEFAULT_UDPSTREAM_PERCENTILE_COUNT, DEFAULT_UDPSTREAM_RTT_SAMPLES,
            0xe0, 0},

        {0, DEFAULT_TEST_PORT, 1025, 1026, 1027, 1028, 1029, 0x38, 0},

        {0, 65535, MAXIMUM_UDPSTREAM_PACKET_LENGTH,
            65535, 1000000, 1234567, 54321, 0x88, 0},

        {0, 65535, 65535, 65535, 65535, 4294967295, 4294967295,
            0xb8, 0},
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
        if ( send_control_hello(AMP_TEST_UDPSTREAM, sendctrl,
                    build_hello(&optionsA[i])) < 0 ) {
            return -1;
        }

        /* read it out the other and make sure it matches what we sent */
        if ( read_control_hello(AMP_TEST_UDPSTREAM, recvctrl,
                    (void**)&optionsB, parse_hello) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(optionsA[i].tport == optionsB->tport);
        assert(optionsA[i].packet_size == optionsB->packet_size);
        assert(optionsA[i].packet_count == optionsB->packet_count);
        assert(optionsA[i].packet_spacing == optionsB->packet_spacing);
        assert(optionsA[i].percentile_count == optionsB->percentile_count);
        assert(optionsA[i].rtt_samples == optionsB->rtt_samples);
        assert(optionsA[i].dscp == optionsB->dscp);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
