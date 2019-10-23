/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Authors: Richard Sanger
 *          Brendon Jones
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

#ifndef _TESTS_THROUGHPUT_H
#define _TESTS_THROUGHPUT_H

#include <netdb.h>
#include <stdint.h>

#include "tests.h"
#include "throughput.pb-c.h"
#include "tcpinfo.h"

/* The default test time in seconds */
#define DEFAULT_TESTTIME  20

/* The default test port */
#define DEFAULT_CONTROL_PORT  8815 /* Could use etc/services like old code */
#define MAX_CONTROL_PORT  8825
#define DEFAULT_TEST_PORT 8826 /* Run test across a separate port */
#define MAX_TEST_PORT 8836
#define DEFAULT_WRITE_SIZE  (128 * 1024) // 128-kbyte like iperf uses
#define DEFAULT_TEST_DURATION 10 /* iperf default: 10s */
#define MAX_MALLOC 20e6

#define MAXSAMPLES 1024 /* Number of samples to take of RTTs */

/*
 * Used as shortcuts for scheduling common tests through the web interface.
 * Some degree of overlap with the tput_type enum which is annoying, and these
 * also have to be specified by number on the command line, which is why they
 * are currently intended to be used only by generated schedule files.
 */
enum tput_schedule_direction {
    DIRECTION_NOT_SET = -1,
    CLIENT_TO_SERVER = 0,
    SERVER_TO_CLIENT = 1,
    CLIENT_THEN_SERVER = 2,
    SERVER_THEN_CLIENT = 3,
};

enum tput_type {
    TPUT_NULL = 0,
    TPUT_2_CLIENT,
    TPUT_2_SERVER,
    TPUT_PAUSE,
    TPUT_NEW_CONNECTION,
};

enum tput_protocol {
    TPUT_PROTOCOL_NONE = 0,
    TPUT_PROTOCOL_HTTP_POST = 1,
};


amp_test_result_t* run_throughput(int argc, char *argv[], int count,
        struct addrinfo **dests);
test_t *register_test(void);
void run_throughput_server(int argc, char *argv[], BIO *ctrl);
amp_test_result_t* run_throughput_client(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_throughput(amp_test_result_t *result);
void usage(void);


/* internal format for holding tcpinfo results if present */
struct tcpinfo_result_t {
    uint64_t delivery_rate;
    uint64_t busy_time;
    uint64_t rwnd_limited;
    uint64_t sndbuf_limited;
    uint32_t total_retrans;
    uint32_t rtt;
    uint32_t rttvar;
    uint32_t min_rtt;
    uint32_t congestion_type;
};

/**
 * A internal format for holding a test result
 */
struct test_result_t {
    uint32_t write_size; /* XXX write_size seems a bit pointless maybe remove it?? */
    uint64_t bytes; /* Bytes seen */
    uint64_t start_ns; /* Start time in nanoseconds */
    uint64_t end_ns; /* End time in nanoseconds */
    struct tcpinfo_result_t *tcpinfo;
};


/* A single request */
struct test_request_t {
    enum tput_type type;
    enum tput_protocol protocol;
    uint64_t bytes;
    uint32_t duration;
    uint32_t write_size;
    uint32_t randomise;
    struct test_result_t *result;
    struct test_request_t *next;
};

/* sample set of rtt timmings */
struct rtt_samples_t {
    char samples[MAXSAMPLES];
    int rttcount;
    int keep_recording;
};


/*
 * Global test options that control packet size and timing.
 */
struct opt_t {
    enum tput_protocol protocol;
    uint16_t cport; /* The control port to connect to */
    uint16_t tport; /* The test port to connect to or create */
    uint32_t write_size; /* The TCP write size to use */
    int32_t sock_mss; /* Set the TCP Maximun segment size */
    uint8_t sock_disable_nagle; /* 0 enable nagale - 1 disable - overriden by /proc/net/tcp/nagle */
    uint8_t randomise;	/* Randomise every packet otherwise continually reuse the same random packet */
    uint8_t disable_web10g;
    uint8_t reuse_addr;
    int32_t sock_rcvbuf;
    int32_t sock_sndbuf;
    uint8_t dscp;
    char *textual_schedule;
    struct test_request_t *schedule; /* The test sequence */
    char *device;
    struct addrinfo *sourcev4;
    struct addrinfo *sourcev6;
};

/* All of our packet types */
enum TPUT_PKT {
    TPUT_PKT_DATA = 0,
    TPUT_PKT_SEND = 1,
    TPUT_PKT_RESULT = 2,
    TPUT_PKT_CLOSE = 3,
    TPUT_PKT_RENEW_CONNECTION = 4,
    TPUT_PKT_HELLO = 5,
    TPUT_PKT_READY = 6,
};


/* Shared common functions from throughput_common.c */
Amplet2__Throughput__Item* report_schedule(struct test_request_t *info);

/* do outgoing test */
int sendStream(int sock_fd, struct test_request_t *test_opts,
        struct test_result_t *res);

/* Receive incoming test */
int incomingTest(int sock_fd, struct test_result_t *result);
int writeBuffer(int sock_fd, void *packet, size_t length,
        struct rtt_samples_t * rtt_samples);
int readBuffer(int test_socket);

uint64_t timeNanoseconds(void);
ProtobufCBinaryData* build_hello(struct opt_t *options);
ProtobufCBinaryData* build_send(struct test_request_t *options);
void* parse_hello(ProtobufCBinaryData *data);
void* parse_send(ProtobufCBinaryData *data);

#if UNIT_TEST
amp_test_result_t* amp_test_report_results(uint64_t start_time,
        struct addrinfo *dest, struct opt_t *options);
#endif

#endif /* _TESTS_THROUGHPUT_H */
