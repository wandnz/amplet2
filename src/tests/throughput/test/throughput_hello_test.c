#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "throughput.h"

/*
 * Check that the throughput test hello messages are sensible.
 */
int main(void) {
    int pipefd[2];
    struct packet_t packet;
    uint32_t version;
    int bytes_read, bytes_written;
    /* X tport X mss nagle rand web10g X rcv snd X X X X X */
    struct opt_t optionsA[] = {
        { 0, 12345, 0, 1460, 0, 0, 1, 0, 0, 0, 0,0,0,0,0},
        { 0, 1, 0, 536, 0, 1, 0, 0, 4096, 0, 0,0,0,0,0},
        { 0, DEFAULT_CONTROL_PORT, 0, 1220, 0, 1, 1, 0, 0, 4096, 0,0,0,0,0},
        { 0, DEFAULT_TEST_PORT, 0, 5960, 1, 0, 0, 0, 4096, 4096, 0, 0, 0, 0, 0},
        { 0, 65535, 0, 8960, 1, 1, 1, 0, 1234, 5678, 0, 0, 0, 0, 0},
        { 0, 65535, 0, 8960, 0, 0, 0, 0, 98765, 54321, 0, 0, 0, 0, 0},
    };
    struct opt_t optionsB;
    int count;
    int i;

    count = sizeof(optionsA) / sizeof(struct opt_t);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    /* try sending each of the test option sets */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        bytes_written = sendHelloPacket(pipefd[1], &optionsA[i]);
        assert(bytes_written == sizeof(struct packet_t));

        /* read it out the other and make sure it matches what we sent */
        memset(&packet, 0, sizeof(packet));
        bytes_read = readPacket(pipefd[0], &packet, NULL);

        assert(bytes_read == sizeof(struct packet_t));
        assert(bytes_written == bytes_read);

        /* parse the hello packet */
        memset(&optionsB, 0, sizeof(optionsB));
        if ( readHelloPacket(&packet, &optionsB, &version) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(version == AMP_THROUGHPUT_TEST_VERSION);
        assert(packet.header.type == TPUT_PKT_HELLO);
        assert(optionsA[i].sock_disable_nagle == optionsB.sock_disable_nagle);
        assert(optionsA[i].disable_web10g == optionsB.disable_web10g);
        assert(optionsA[i].randomise == optionsB.randomise);
        assert(optionsA[i].tport == optionsB.tport);
        assert(optionsA[i].sock_mss == optionsB.sock_mss);
        assert(optionsA[i].sock_rcvbuf == optionsB.sock_rcvbuf);
        assert(optionsA[i].sock_sndbuf == optionsB.sock_sndbuf);
    }

    close(pipefd[0]);
    close(pipefd[1]);
    return 0;
}
