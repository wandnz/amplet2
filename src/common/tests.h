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

#ifndef _COMMON_TESTS_H
#define _COMMON_TESTS_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/bio.h>

/* TODO move elsewhere to more global config file */
#define MAX_PATH_LENGTH 10000

typedef enum {
    AMP_TEST_INVALID,
    AMP_TEST_SKELETON,
    AMP_TEST_ICMP,
    AMP_TEST_DNS,
    AMP_TEST_TRACEROUTE,
    AMP_TEST_HTTP,
    AMP_TEST_THROUGHPUT,
    AMP_TEST_TCPPING,
    AMP_TEST_REMOTE_SKELETON,
    AMP_TEST_UDPSTREAM,
    AMP_TEST_YOUTUBE,
    AMP_TEST_LAST,
} test_type_t;

typedef struct amp_test_result {
    uint64_t timestamp;
    size_t len;
    void *data;
} amp_test_result_t;

typedef struct test {
    /* */
    test_type_t id;

    /*
     * Name of the test, used for schedule files and reporting. It is
     * traditionally fairly short though still descriptive, a single word
     * with no spaces.
     */
    char *name;

    /*
     * Maximum number of targets this test can operate on in a single instance.
     * If more targets are specified then multiple instances of the test will
     * be run. A value of 0 means there is no limit.
     */
    uint16_t max_targets;

    /*
     * Minimum number of targets this test needs before it will run. Some tests
     * have default values that will automatically add targets if there are
     * none configured, other tests receive their targets through command line
     * arguments and don't require normal destinations.
     */
    uint16_t min_targets;

    /*
     * Maximum duration in seconds that this test can run for. If the test runs
     * for longer than this it will be killed with a SIGKILL.
     */
    uint16_t max_duration;

    /*
     * Pointer to a function that will perform any pre-test configuration that
     * is required (such as asking a remote measured process to start server
     * programs or negotiating port numbers). It is also a chance to add any
     * negotiated or calculated values as command line options to the test
     * binary. This function is also responsible for starting the test.
     */
    amp_test_result_t* (*run_callback)(int argc, char *argv[], int count,
	    struct addrinfo **dests);

    /*
     * Pointer to a function that will pretty print the test results when
     * the test is run as a standalone program rather than as part of
     * measured.
     */
    void (*print_callback)(amp_test_result_t *result);

    /*
     * Pointer to a function that will start up the server portion of a test
     * if required.
     */
    void (*server_callback)(int argc, char *argv[], BIO *ctrl);

    /*
     * Pointer to the module that implements the callback functions for
     * this test.
     */
    void *dlhandle;

    /*
     * true if the test should be sent a SIGINT before being sent a SIGKILL
     * when it runs out of time, false if it should just be sent the SIGKILL.
     * This can be useful to report partial results from a test that tests to
     * multiple locations.
     */
     int sigint;

} test_t;


typedef test_t * (*test_reg_ptr) (void);

#endif
