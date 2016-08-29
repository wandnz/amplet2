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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "tests.h"
#include "udpstream.h"
#include "controlmsg.h"

/*
 * Check that the udpstream test ready messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
    uint16_t ports[] = {
        1, 100, 1024, 1025, 8816, 8817, 8826, 8827, 12345, 65535
    };
    uint16_t tport;
    int count;
    int i;

    count = sizeof(ports) / sizeof(int);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    sendctrl = BIO_new_socket(pipefd[1], BIO_CLOSE);
    recvctrl = BIO_new_socket(pipefd[0], BIO_CLOSE);

    /* try sending each of the test ports */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        if ( send_control_ready(AMP_TEST_UDPSTREAM, sendctrl,ports[i]) < 0 ) {
            return -1;
        }

        /* read it out the other and make sure it matches what we sent */
        if ( read_control_ready(AMP_TEST_UDPSTREAM, recvctrl, &tport) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(ports[i] == tport);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
