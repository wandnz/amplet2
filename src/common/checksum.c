/*
 * Copyright (c) 1988 IETF Trust, R. Braden, D.Borman, C. Partridge.
 * All rights reserved.
 *
 * From RFC 1071 "Computing the Internet Checksum" 1988.
 */

#include <stdint.h>
#include "checksum.h"



/*
 * Calculate the icmp header checksum.
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
