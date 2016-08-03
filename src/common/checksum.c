/*
 * Copyright (c) 1988 IETF Trust, R. Braden, D.Borman, C. Partridge.
 * All rights reserved.
 *
 * The RFC is old enough to predate all the RFCs that discuss licensing. Code
 * samples in recent RFCs are available under the 3 clause BSD license. The
 * best I can find for RFC1071 is:
 *
 *     "Distribution of this memo is unlimited."
 *
 * and there is little point in putting code samples in such a document and
 * not expecting them to be used.
 *
 * TODO can we confirm what license this is under?
 */


#include <stdint.h>
#include "checksum.h"



/*
 * Calculate the icmp header checksum. Based on the example C code algorithm
 * given in RFC1071 "Computing the Internet Checksum".
 */
uint16_t checksum(uint16_t *data, int length) {
    uint64_t sum = 0;

    while ( length > 1 ) {
        sum += *data++;
        length -= 2;
    }

    if ( length > 0 ) {
        sum += *(unsigned char *)data;
    }

    while ( sum >> 16 ) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}
