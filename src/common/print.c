/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2022 The University of Waikato, Hamilton, New Zealand.
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

#include <stdio.h>
#include <stdint.h>

#include "print.h"


/*
 * Print out a size value using sensible units.
 */
void print_formatted_bytes(uint64_t bytes) {
    double scaled = (double)bytes;
    char *units[] = {"bytes", "KiB", "MiB", "GiB", NULL};
    char **unit;

    for ( unit = units; *unit != NULL; unit++ ) {
        if ( scaled < 1024 ) {
            printf("%.02lf %s", scaled, *unit);
            return;
        }
        scaled = scaled / 1024.0;
    }

    printf("%.02lf TiB", scaled);
}



/*
 * Print out a duration value using seconds.
 */
void print_formatted_duration(uint64_t time_us) {
    printf("%.02lf seconds", ((double)time_us) / 1000000);
}



/**
 * Print out a speed in a factor of bits per second
 * Kb = 1000 * b
 * Mb = 1000 * Kb etc
 */
void print_formatted_speed(uint64_t bytes, uint64_t time_us) {
    double x_per_sec;
    char *units[] = {"bits", "Kbits", "Mbits", "Gbits", NULL};
    char **unit;

    if ( bytes == 0 || time_us == 0 ) {
        x_per_sec = 0;
    } else {
        x_per_sec = ((double)bytes * 8.0) / ((double) time_us / 1e6);
    }

    for ( unit = units; *unit != NULL; unit++ ) {
        if ( x_per_sec < 1000 ) {
            printf("%.02lf %s/sec", x_per_sec, *unit);
            return;
        }
        x_per_sec = x_per_sec / 1000;
    }

    printf("%.02lf Tb/s", x_per_sec);
}
