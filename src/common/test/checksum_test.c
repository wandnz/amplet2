/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

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
