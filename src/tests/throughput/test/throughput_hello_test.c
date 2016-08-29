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
#include "serverlib.h"
#include "controlmsg.h"

/*
 * Check that the throughput test hello messages are sensible.
 */
int main(void) {
    int pipefd[2];
    BIO *sendctrl, *recvctrl;
    /* X tport X mss nagle rand web10g X rcv snd dscp X X X X X */
    struct opt_t optionsA[] = {
        { 0, 12345, 0, 1460, 0, 0, 1, 0, 0, 0, 0, 0,0,0,0,0},
        { 0, 1, 0, 536, 0, 1, 0, 0, 4096, 0, 0x20, 0,0,0,0,0},
        { 0, DEFAULT_CONTROL_PORT, 0, 1220, 0, 1, 1, 0, 0, 4096, 0xe0, 0,0,0,0,0},
        { 0, DEFAULT_TEST_PORT, 0, 5960, 1, 0, 0, 0, 4096, 4096, 0x38, 0,0,0,0,0},
        { 0, 65535, 0, 8960, 1, 1, 1, 0, 1234, 5678, 0x88, 0,0,0,0,0},
        { 0, 65535, 0, 8960, 0, 0, 0, 0, 98765, 54321, 0xb8, 0,0,0,0,0},
    };
    struct opt_t *optionsB;
    int count;
    int i;

    count = sizeof(optionsA) / sizeof(struct opt_t);

    /* create the pipe that will be our pretend network connection */
    if ( pipe(pipefd) < 0 ) {
        return -1;
    }

    sendctrl = BIO_new_socket(pipefd[1], BIO_CLOSE);
    recvctrl = BIO_new_socket(pipefd[0], BIO_CLOSE);

    /* try sending each of the test option sets */
    for ( i = 0; i < count; i++ ) {
        /* write data into one end of the pipe */
        if ( send_control_hello(AMP_TEST_THROUGHPUT, sendctrl,
                    build_hello(&optionsA[i])) < 0 ) {
            return -1;
        }

        /* read it out the other and make sure it matches what we sent */
        if ( read_control_hello(AMP_TEST_THROUGHPUT, recvctrl,
                    (void**)&optionsB, parse_hello) != 0 ) {
            return -1;
        }

        /* check everything we received matches what we sent */
        assert(optionsA[i].sock_disable_nagle == optionsB->sock_disable_nagle);
        assert(optionsA[i].disable_web10g == optionsB->disable_web10g);
        assert(optionsA[i].randomise == optionsB->randomise);
        assert(optionsA[i].tport == optionsB->tport);
        assert(optionsA[i].sock_mss == optionsB->sock_mss);
        assert(optionsA[i].sock_rcvbuf == optionsB->sock_rcvbuf);
        assert(optionsA[i].sock_sndbuf == optionsB->sock_sndbuf);
        assert(optionsA[i].dscp == optionsB->dscp);
    }

    BIO_free_all(sendctrl);
    BIO_free_all(recvctrl);

    return 0;
}
