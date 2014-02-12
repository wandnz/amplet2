#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "tests.h"
#include "icmp.h"

#define MAXLEN 32
/*
 * Check that the icmp test is correctly performing checksums.
 *
 * We could do some more testing on less regular patterns if we really
 * felt that there was a need for it, but this gives us some basic coverage.
 */
int main(int argc, char *argv[]) {
    char packet[MAXLEN];

    /* all zeroes */
    memset(packet, 0, MAXLEN);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 1) == 0xffff);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 2) == 0xffff);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 4) == 0xffff);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 8) == 0xffff);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 16) == 0xffff);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 32) == 0xffff);

    /* all ones */
    memset(packet, 0xff, MAXLEN);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 1) == 0xff00);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 2) == 0x0000);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 4) == 0x0000);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 8) == 0x0000);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 16) == 0x0000);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 32) == 0x0000);

    /* last bit per byte set */
    memset(packet, 0x01, MAXLEN);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 1) == 0xfffe);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 2) == 0xfefe);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 4) == 0xfdfd);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 8) == 0xfbfb);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 16) == 0xf7f7);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 32) == 0xefef);

    /* last bit per nibble set */
    memset(packet, 0x11, MAXLEN);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 1) == 0xffee);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 2) == 0xeeee);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 4) == 0xdddd);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 8) == 0xbbbb);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 16) == 0x7777);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 32) == 0xeeee);

    /* every second bit set */
    memset(packet, 0xaa, MAXLEN);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 1) == 0xff55);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 2) == 0x5555);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 4) == 0xaaaa);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 8) == 0x5555);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 16) == 0xaaaa);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 32) == 0x5555);

    /* arbitrary pattern set 10010011 */
    memset(packet, 0x93, MAXLEN);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 1) == 0xff6c);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 2) == 0x6c6c);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 4) == 0xd8d8);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 8) == 0xb1b1);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 16) == 0x6363);
    assert(amp_test_icmp_checksum((uint16_t*)packet, 32) == 0xc6c6);

    return 0;
}
