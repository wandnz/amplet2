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

#ifndef _TESTS_NDT_H
#define _TESTS_NDT_H

#include <sys/types.h>
#include <stdint.h>
#include <sys/time.h>

#include "testlib.h"

/*
 * User defined test options.
 */
struct test_options {
    uint32_t write_size;
    uint32_t sock_rcvbuf;
    uint32_t sock_sndbuf;
    uint32_t perturbate;	/* delay sending by up to this time (usec) */
    uint8_t dscp;               /* diffserv codepoint to set */
    uint8_t ssl;                /* true if wss, false if ws scheme */
    char *device;
    struct addrinfo *sourcev4;
    struct addrinfo *sourcev6;
    char *urlstr;
};

struct decomposed_uri {
    const char *scheme;
    const char *host;
    int port;
    const char *path;
};

struct ndt_stats {
    int direction;
    uint64_t bytes;
    struct timeval start;
    struct timeval end;
    struct tcpinfo_result *tcpinfo;
    struct sockaddr *addr;
    char *name;
    char *city;
    char *country;
};

amp_test_result_t* run_ndt(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_ndt(amp_test_result_t *result);
test_t *register_test(void);

#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct test_options *opt);
#endif


#endif
