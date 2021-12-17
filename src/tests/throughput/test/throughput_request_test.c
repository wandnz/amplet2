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
#include "throughput.h"
#include "controlmsg.h"

/*
 * Check that the throughput test request messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
    /* direction X bytes duration write_size X X X */
    struct test_request_t *request;
    struct test_request_t requests[] = {
        { AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            0, 0, 0, 0, 0, 0, 0 },
        { AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            0, 1024, 0, 128, 0, 0, 0 },
        { AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            0, 10*1024*1024, 0, 1024, 0, 0, 0 },
        { AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            0, 0, 10, 4096, 0, 0, 0 },
        { AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT,
            0, 0, 60, 4096, 0, 0, 0 },
        { AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER,
            0, 0, 300, 12345, 0, 0, 0 },
    };
    void *data;
    int bytes;
    int count;
    int i;

    count = sizeof(requests) / sizeof(struct test_request_t);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    sendctrl = BIO_new_socket(pipefd[1], BIO_CLOSE);
    recvctrl = BIO_new_socket(pipefd[0], BIO_CLOSE);

    /* try sending each of the test option sets */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        if ( send_control_send(AMP_TEST_THROUGHPUT, sendctrl,
                    build_send(&requests[i])) < 0 ) {
            return -1;
        }

        /* read it out the other end... */
        if ( (bytes=read_control_packet(recvctrl, &data)) < 0 ) {
            return -1;
        }

        /* ... and make sure it matches what we sent */
        if ( parse_control_send(AMP_TEST_THROUGHPUT, data, bytes,
                    (void**)&request, parse_send) < 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(requests[i].bytes == request->bytes);
        assert(requests[i].duration == request->duration);
        assert(requests[i].write_size == request->write_size);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
