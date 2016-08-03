#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "checksum.h"

#define MAXLEN 32
/*
 * Check that checksums are being correctly calculated.
 *
 * We could do some more testing on less regular patterns if we really
 * felt that there was a need for it, but this gives us some basic coverage.
 */
int main(void) {
    char buffer[MAXLEN];

    /* all zeroes */
    memset(buffer, 0, MAXLEN);
    assert(checksum((uint16_t*)buffer, 1) == 0xffff);
    assert(checksum((uint16_t*)buffer, 2) == 0xffff);
    assert(checksum((uint16_t*)buffer, 4) == 0xffff);
    assert(checksum((uint16_t*)buffer, 8) == 0xffff);
    assert(checksum((uint16_t*)buffer, 16) == 0xffff);
    assert(checksum((uint16_t*)buffer, 32) == 0xffff);

    /* all ones */
    memset(buffer, 0xff, MAXLEN);
    assert(checksum((uint16_t*)buffer, 1) == 0xff00);
    assert(checksum((uint16_t*)buffer, 2) == 0x0000);
    assert(checksum((uint16_t*)buffer, 4) == 0x0000);
    assert(checksum((uint16_t*)buffer, 8) == 0x0000);
    assert(checksum((uint16_t*)buffer, 16) == 0x0000);
    assert(checksum((uint16_t*)buffer, 32) == 0x0000);

    /* last bit per byte set */
    memset(buffer, 0x01, MAXLEN);
    assert(checksum((uint16_t*)buffer, 1) == 0xfffe);
    assert(checksum((uint16_t*)buffer, 2) == 0xfefe);
    assert(checksum((uint16_t*)buffer, 4) == 0xfdfd);
    assert(checksum((uint16_t*)buffer, 8) == 0xfbfb);
    assert(checksum((uint16_t*)buffer, 16) == 0xf7f7);
    assert(checksum((uint16_t*)buffer, 32) == 0xefef);

    /* last bit per nibble set */
    memset(buffer, 0x11, MAXLEN);
    assert(checksum((uint16_t*)buffer, 1) == 0xffee);
    assert(checksum((uint16_t*)buffer, 2) == 0xeeee);
    assert(checksum((uint16_t*)buffer, 4) == 0xdddd);
    assert(checksum((uint16_t*)buffer, 8) == 0xbbbb);
    assert(checksum((uint16_t*)buffer, 16) == 0x7777);
    assert(checksum((uint16_t*)buffer, 32) == 0xeeee);

    /* every second bit set */
    memset(buffer, 0xaa, MAXLEN);
    assert(checksum((uint16_t*)buffer, 1) == 0xff55);
    assert(checksum((uint16_t*)buffer, 2) == 0x5555);
    assert(checksum((uint16_t*)buffer, 4) == 0xaaaa);
    assert(checksum((uint16_t*)buffer, 8) == 0x5555);
    assert(checksum((uint16_t*)buffer, 16) == 0xaaaa);
    assert(checksum((uint16_t*)buffer, 32) == 0x5555);

    /* arbitrary pattern set 10010011 */
    memset(buffer, 0x93, MAXLEN);
    assert(checksum((uint16_t*)buffer, 1) == 0xff6c);
    assert(checksum((uint16_t*)buffer, 2) == 0x6c6c);
    assert(checksum((uint16_t*)buffer, 4) == 0xd8d8);
    assert(checksum((uint16_t*)buffer, 8) == 0xb1b1);
    assert(checksum((uint16_t*)buffer, 16) == 0x6363);
    assert(checksum((uint16_t*)buffer, 32) == 0xc6c6);

    return 0;
}
