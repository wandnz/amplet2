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

/**
 * The AMP throughput test header.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */

#ifndef _TESTS_THROUGHPUT_H
#define _TESTS_THROUGHPUT_H


#include <netdb.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <getopt.h>

#include "tests.h"
#include "throughput.pb-c.h"

/* The default test time in seconds */
#define DEFAULT_TESTTIME  20

/* The default test port */
#define DEFAULT_CONTROL_PORT  8815 /* Could use etc/services like old code */
#define MAX_CONTROL_PORT  8825
#define DEFAULT_TEST_PORT 8826 /* Run test across a separate port */
#define MAX_TEST_PORT 8836
#define DEFAULT_WRITE_SIZE  (128 * 1024) // 128-kbyte like iperf uses
#define DEFAULT_TPUT_PAUSE  10000
#define DEFAULT_TEST_DURATION 10 /* iperf default: 10s */


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
amp_test_result_t* run_throughput(int argc, char *argv[], int count,
        struct addrinfo **dests);
test_t *register_test(void);
void run_throughput_server(int argc, char *argv[], BIO *ctrl);
amp_test_result_t* run_throughput_client(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_throughput(amp_test_result_t *result);
void usage(void);




#define MAX_MALLOC 20e6

/**
 * The very large structure holding everything we can get from web10g
 * TODO convert to protocol buffers
 *
 * sizeof(struct report_web10g_t) == 480
 */
struct report_web10g_t {
    uint64_t HCDataOctetsOut;
    uint64_t HCDataOctetsIn;
    uint64_t HCSumRTT;
    uint64_t HCThruOctetsAcked;
    uint64_t HCThruOctetsReceived;

    uint32_t SegsOut;
    uint32_t DataSegsOut;
    uint32_t DataOctetsOut;
    uint32_t SegsRetrans;
    uint32_t OctetsRetrans;
    uint32_t SegsIn;
    uint32_t DataSegsIn;
    uint32_t DataOctetsIn;
    uint32_t ElapsedSecs;
    uint32_t ElapsedMicroSecs;
    uint32_t CurMSS;
    uint32_t PipeSize;
    uint32_t MaxPipeSize;
    uint32_t SmoothedRTT;
    uint32_t CurRTO;
    uint32_t CongSignals;
    uint32_t CurCwnd;
    uint32_t CurSsthresh;
    uint32_t Timeouts;
    uint32_t CurRwinSent;
    uint32_t MaxRwinSent;
    uint32_t ZeroRwinSent;
    uint32_t CurRwinRcvd;
    uint32_t MaxRwinRcvd;
    uint32_t ZeroRwinRcvd;
    uint32_t SndLimTransRwin;
    uint32_t SndLimTransCwnd;
    uint32_t SndLimTransSnd;
    uint32_t SndLimTimeRwin;
    uint32_t SndLimTimeCwnd;
    uint32_t SndLimTimeSnd;
    uint32_t RetranThresh;
    uint32_t NonRecovDAEpisodes;
    uint32_t SumOctetsReordered;
    uint32_t NonRecovDA;
    uint32_t SampleRTT;
    uint32_t RTTVar;
    uint32_t MaxRTT;
    uint32_t MinRTT;
    uint32_t SumRTT;
    uint32_t CountRTT;
    uint32_t MaxRTO;
    uint32_t MinRTO;
    uint32_t IpTtl;
    uint32_t PreCongSumCwnd;
    uint32_t PreCongSumRTT;
    uint32_t PostCongSumRTT;
    uint32_t PostCongCountRTT;
    uint32_t ECNsignals;
    uint32_t DupAckEpisodes;
    uint32_t RcvRTT;
    uint32_t DupAcksOut;
    uint32_t CERcvd;
    uint32_t ECESent;
    int32_t ActiveOpen;
    uint32_t MSSSent;
    uint32_t MSSRcvd;
    int32_t WinScaleSent;
    int32_t WinScaleRcvd;
    int32_t TimeStamps;
    int32_t ECN;
    int32_t WillSendSACK;
    int32_t WillUseSACK;
    int32_t State;
    int32_t Nagle;
    uint32_t MaxSsCwnd;
    uint32_t MaxCaCwnd;
    uint32_t MaxSsthresh;
    uint32_t MinSsthresh;
    int32_t InRecovery;
    uint32_t DupAcksIn;
    uint32_t SpuriousFrDetected;
    uint32_t SpuriousRtoDetected;
    uint32_t SoftErrors;
    int32_t SoftErrorReason;
    uint32_t SlowStart;
    uint32_t CongAvoid;
    uint32_t OtherReductions;
    uint32_t CongOverCount;
    uint32_t FastRetran;
    uint32_t SubsequentTimeouts;
    uint32_t CurTimeoutCount;
    uint32_t AbruptTimeouts;
    uint32_t SACKsRcvd;
    uint32_t SACKBlocksRcvd;
    uint32_t SendStall;
    uint32_t DSACKDups;
    uint32_t MaxMSS;
    uint32_t MinMSS;
    uint32_t SndInitial;
    uint32_t RecInitial;
    uint32_t CurRetxQueue;
    uint32_t MaxRetxQueue;
    uint32_t CurReasmQueue;
    uint32_t MaxReasmQueue;
    uint32_t SndUna;
    uint32_t SndNxt;
    uint32_t SndMax;
    uint32_t ThruOctetsAcked;
    uint32_t RcvNxt;
    uint32_t ThruOctetsReceived;
    uint32_t CurAppWQueue;
    uint32_t MaxAppWQueue;
    uint32_t CurAppRQueue;
    uint32_t MaxAppRQueue;
    uint32_t LimCwnd;
    uint32_t LimSsthresh;
    uint32_t LimRwin;
    uint32_t LimMSS;


    int8_t StartTimeStamp;
    uint8_t IpTosIn;
    uint8_t IpTosOut;
    uint8_t __PADDING1;

};

/**
 * A internal format for holding a test result
 */
struct test_result_t {
    uint32_t packets; /* packet count */
    uint32_t write_size; /* XXX write_size seems a bit pointless maybe remove it?? */
    uint64_t bytes; /* Bytes seen */
    uint64_t start_ns; /* Start time in nanoseconds */
    uint64_t end_ns; /* End time in nanoseconds */
    uint32_t done; /* This test has completed */
};

/* A single request */
struct test_request_t {
    enum tput_type type;
    uint64_t bytes;
    uint32_t duration; /* pause duration in milliseconds */
    uint32_t write_size;
    uint32_t randomise;

    /* Result for the client and server - these should almost be identical */
    struct test_result_t *c_result;
    struct test_result_t *s_result;

    /* Web10g results again should mirror each other but interesting to see if they do */
    struct report_web10g_t *c_web10g;
    struct report_web10g_t *s_web10g;

    struct test_request_t *next;
};


/*
 * Global test options that control packet size and timing.
 */
struct opt_t {
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
/* This should align correctly under
 * sizeof(struct packet_t) == 32
 */
/* TODO remove most of this, unnecessary */
struct packet_t {
    struct header_t {
        uint32_t type;
        uint32_t size; /* Size excluding header sizeof(struct packet_t) */
    } header;
    union type_t {
        struct dataPacket_t {
            uint32_t  more;
        } data;
    } types; //type union
}; //packet_t struct


/* Shared common functions from throughput_common.c */
Amplet2__Throughput__Item* report_schedule(struct test_request_t *info);
int readDataPacket(const struct packet_t *packet, const int write_size,
        struct test_result_t *res);

/* do outgoing test */
int sendPackets(int sock_fd,
                    struct test_request_t *test_opts,
                    struct test_result_t *res);
/* Receive incoming test */
int incomingTest(int sock_fd, struct test_result_t *result);
/* Read write individual packets */
int writePacket(int sock_fd, struct packet_t *packet);
int readPacket(int test_socket, struct packet_t *packet,
                    char **additional);

uint64_t timeNanoseconds(void);
ProtobufCBinaryData* build_hello(struct opt_t *options);
ProtobufCBinaryData* build_send(struct test_request_t *options);
void* parse_hello(ProtobufCBinaryData *data);
void* parse_send(ProtobufCBinaryData *data);

/*
 * Shared function from web10g.c
 */
void print_web10g(struct report_web10g_t * web10g);

#if 0
#ifdef HAVE_ESTATS
struct report_web10g_t * getWeb10GSnap(int socket);
#else
#define getWeb10GSnap(sock) NULL
#endif
#endif

#if UNIT_TEST
amp_test_result_t* amp_test_report_results(uint64_t start_time,
        struct addrinfo *dest, struct opt_t *options);
#endif

#endif /* _TESTS_THROUGHPUT_H */
