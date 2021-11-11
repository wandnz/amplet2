/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2021 The University of Waikato, Hamilton, New Zealand.
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timex.h>
#include <unistd.h>

#include "debug.h"
#include "clock.h"

/*
 * systemd-time-wait-sync doesn't appear to notice the final adjustment that
 * synchronises the clock, and ntpd doesn't appear to touch the file
 * /run/systemd/timesync/synchronized when synchronised, so
 * systemd-time-wait-sync ends up hanging indefinitely on boot. Let's just
 * poll adjtimex() until the clock is sychronised.
 */
static int is_clock_synchronised(void) {
    struct timex tx;
    int r;

    memset(&tx, 0, sizeof(struct timex));
    r = adjtimex(&tx);

    if ( r < 0 ) {
        Log(LOG_ALERT, "Failed to get clock sync state: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return r != TIME_ERROR;
}

void wait_for_clock_sync(void) {
    while ( !is_clock_synchronised() ) {
        sleep(30);
    }
}
