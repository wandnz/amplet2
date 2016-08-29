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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "dscp.h"



/*
 * Convert differentiated services code point value to short printable string.
 */
char *dscp_to_str(const uint8_t value) {
    switch ( value ) {
        case 0: return "default";
        case 0b001000: return "cs1";
        case 0b010000: return "cs2";
        case 0b011000: return "cs3";
        case 0b100000: return "cs4";
        case 0b101000: return "cs5";
        case 0b110000: return "cs6";
        case 0b111000: return "cs7";
        case 0b001010: return "af11";
        case 0b001100: return "af12";
        case 0b001110: return "af13";
        case 0b010010: return "af21";
        case 0b010100: return "af22";
        case 0b010110: return "af23";
        case 0b011010: return "af31";
        case 0b011100: return "af32";
        case 0b011110: return "af33";
        case 0b100010: return "af41";
        case 0b100100: return "af42";
        case 0b100110: return "af43";
        case 0b101100: return "va";
        case 0b101110: return "ef";
        /* TODO return the value in a static buffer? */
        default: return "non-standard";
    };
}



/*
 * Parse a string from the command line to extract a differentiated services
 * code point value. If a known value isn't found it will try to interpret the
 * string as a binary, octal, hex or decimal number and use that.
 */
int parse_dscp_value(const char *value, uint8_t *result) {
    /* check if the name of a code point was given, if so set the right value */
    if ( strncasecmp(value, "cs0", strlen("cs0")) == 0 ||
            strncasecmp(value, "none", strlen("none")) == 0 ||
            strncasecmp(value, "default", strlen("default")) == 0 ) {
        *result = 0;
    } else if ( strncasecmp(value, "cs1", strlen("cs1")) == 0 ) {
        *result = 0b001000;
    } else if ( strncasecmp(value, "cs2", strlen("cs2")) == 0 ) {
        *result = 0b010000;
    } else if ( strncasecmp(value, "cs3", strlen("cs3")) == 0 ) {
        *result = 0b011000;
    } else if ( strncasecmp(value, "cs4", strlen("cs4")) == 0 ) {
        *result = 0b100000;
    } else if ( strncasecmp(value, "cs5", strlen("cs5")) == 0 ) {
        *result = 0b101000;
    } else if ( strncasecmp(value, "cs6", strlen("cs6")) == 0 ) {
        *result = 0b110000;
    } else if ( strncasecmp(value, "cs7", strlen("cs7")) == 0 ) {
        *result = 0b111000;
    } else if ( strncasecmp(value, "af11", strlen("af11")) == 0 ) {
        *result = 0b001010;
    } else if ( strncasecmp(value, "af12", strlen("af12")) == 0 ) {
        *result = 0b001100;
    } else if ( strncasecmp(value, "af13", strlen("af13")) == 0 ) {
        *result = 0b001110;
    } else if ( strncasecmp(value, "af21", strlen("af21")) == 0 ) {
        *result = 0b010010;
    } else if ( strncasecmp(value, "af22", strlen("af22")) == 0 ) {
        *result = 0b010100;
    } else if ( strncasecmp(value, "af23", strlen("af23")) == 0 ) {
        *result = 0b010110;
    } else if ( strncasecmp(value, "af31", strlen("af31")) == 0 ) {
        *result = 0b011010;
    } else if ( strncasecmp(value, "af32", strlen("af32")) == 0 ) {
        *result = 0b011100;
    } else if ( strncasecmp(value, "af33", strlen("af33")) == 0 ) {
        *result = 0b011110;
    } else if ( strncasecmp(value, "af41", strlen("af41")) == 0 ) {
        *result = 0b100010;
    } else if ( strncasecmp(value, "af42", strlen("af42")) == 0 ) {
        *result = 0b100100;
    } else if ( strncasecmp(value, "af43", strlen("af43")) == 0 ) {
        *result = 0b100110;
    } else if ( strncasecmp(value, "va", strlen("va")) == 0 ) {
        *result = 0b101100;
    } else if ( strncasecmp(value, "ef", strlen("ef")) == 0 ) {
        *result = 0b101110;
    } else {
        int converted;
        char *endptr;
        /* check if a binary value was given for the DSCP value */
        errno = 0;
        converted = strtol(value, &endptr, 2);
        if ( errno != 0 || *endptr != '\0' || converted >= (1 << 6) ) {
            /* if not, then try base 8, 10 and 16 */
            errno = 0;
            converted = strtol(value, &endptr, 0);
            if ( errno != 0 || *endptr != '\0' || converted >= (1 << 6) ) {
                *result = 0;
                return -1;
            }
        }
        *result = converted;
    }

    return 0;
}
