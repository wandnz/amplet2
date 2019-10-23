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

/**
 * Common functions used by both the throughput client and
 * server
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include "config.h"
#include "throughput.h"
#include "serverlib.h"
#include "debug.h"



/*
 * Build a HELLO protocol buffer message containing test options.
 */
ProtobufCBinaryData* build_hello(struct opt_t *options) {
    ProtobufCBinaryData *data = malloc(sizeof(ProtobufCBinaryData));
    Amplet2__Throughput__Hello hello = AMPLET2__THROUGHPUT__HELLO__INIT;

    hello.has_test_port = 1;
    hello.test_port = options->tport;
    hello.has_mss = 1;
    hello.mss = options->sock_mss;
    hello.has_rcvbuf = 1;
    hello.rcvbuf = options->sock_rcvbuf;
    hello.has_sndbuf = 1;
    hello.sndbuf = options->sock_sndbuf;
    hello.has_disable_nagle = 1;
    hello.disable_nagle = options->sock_disable_nagle;
    hello.has_disable_web10g = 1;
    hello.disable_web10g = options->disable_web10g;
    hello.has_randomise = 1;
    hello.randomise = options->randomise;
    hello.has_reuse_addr = 1;
    hello.reuse_addr = options->reuse_addr;
    hello.has_write_size = 1;
    hello.write_size = options->write_size;
    hello.has_dscp = 1;
    hello.dscp = options->dscp;
    hello.has_protocol = 1;
    hello.protocol = options->protocol;

    data->len = amplet2__throughput__hello__get_packed_size(&hello);
    data->data = malloc(data->len);
    amplet2__throughput__hello__pack(&hello, data->data);

    return data;
}



/*
 * Parse a HELLO protocol buffer message containing test options and return
 * them.
 */
void* parse_hello(ProtobufCBinaryData *data) {
    struct opt_t *options;
    Amplet2__Throughput__Hello *hello;

    hello = amplet2__throughput__hello__unpack(NULL, data->len, data->data);
    options = calloc(1, sizeof(struct opt_t));

    options->tport = hello->test_port;
    options->sock_mss = hello->mss;
    options->sock_rcvbuf = hello->rcvbuf;
    options->sock_sndbuf = hello->sndbuf;
    options->sock_disable_nagle = hello->disable_nagle;
    options->disable_web10g = hello->disable_web10g;
    options->randomise = hello->randomise;
    options->reuse_addr = hello->reuse_addr;
    options->write_size = hello->write_size;
    options->dscp = hello->dscp;
    options->protocol = hello->protocol;

    amplet2__throughput__hello__free_unpacked(hello, NULL);

    return options;
}



/*
 * Build a SEND protocol buffer message containing information on how long
 * to send test data.
 */
ProtobufCBinaryData* build_send(struct test_request_t *options) {
    ProtobufCBinaryData *data = malloc(sizeof(ProtobufCBinaryData));
    Amplet2__Throughput__Send send = AMPLET2__THROUGHPUT__SEND__INIT;

    send.has_duration = 1;
    send.duration = options->duration;
    send.has_write_size = 1;
    send.write_size = options->write_size;
    send.has_bytes = 1;
    send.bytes = options->bytes;

    data->len = amplet2__throughput__send__get_packed_size(&send);
    data->data = malloc(data->len);
    amplet2__throughput__send__pack(&send, data->data);

    return data;
}



/*
 * Parse a SEND protocol buffer message containing information on how long
 * to send test data and return it.
 */
void* parse_send(ProtobufCBinaryData *data) {
    struct test_request_t *options;
    Amplet2__Throughput__Send *send;

    send = amplet2__throughput__send__unpack(NULL, data->len, data->data);
    options = calloc(1, sizeof(struct test_request_t));

    options->duration = send->duration;
    options->write_size = send->write_size;
    options->bytes = send->bytes;

    amplet2__throughput__send__free_unpacked(send, NULL);

    return options;
}



/*
 * Construct a protocol buffer message containing the results for a single
 * element in the test schedule.
 */
Amplet2__Throughput__Item* report_schedule(struct test_request_t *info) {

    Amplet2__Throughput__Item *item =
        (Amplet2__Throughput__Item*)malloc(sizeof(Amplet2__Throughput__Item));

    /* fill the report item with results of a test */
    amplet2__throughput__item__init(item);
    item->has_direction = 1;
    item->direction = info->type;

    if ( info->result == NULL ) {
        Log(LOG_DEBUG, "tput result: test did not run to %s",
                (item->direction ==
                 AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT) ?
                "client" : "server");
        return item;
    }

    item->has_duration = 1;
    item->duration = info->result->end_ns - info->result->start_ns;
    item->has_bytes = 1;
    item->bytes = info->result->bytes;

    /* add the tcpinfo block if there is one */
    if ( info->result->tcpinfo ) {
        item->tcpinfo = calloc(1, sizeof(Amplet2__Throughput__TCPInfo));
        amplet2__throughput__tcpinfo__init(item->tcpinfo);
        item->tcpinfo->has_delivery_rate = 1;
        item->tcpinfo->delivery_rate = info->result->tcpinfo->delivery_rate;
        item->tcpinfo->has_total_retrans = 1;
        item->tcpinfo->total_retrans = info->result->tcpinfo->total_retrans;
        item->tcpinfo->has_rtt = 1;
        item->tcpinfo->rtt = info->result->tcpinfo->rtt;
        item->tcpinfo->has_rttvar = 1;
        item->tcpinfo->rttvar = info->result->tcpinfo->rttvar;
        item->tcpinfo->has_min_rtt = 1;
        item->tcpinfo->min_rtt = info->result->tcpinfo->min_rtt;
        item->tcpinfo->has_busy_time = 1;
        item->tcpinfo->busy_time = info->result->tcpinfo->busy_time;
        item->tcpinfo->has_rwnd_limited = 1;
        item->tcpinfo->rwnd_limited = info->result->tcpinfo->rwnd_limited;
        item->tcpinfo->has_sndbuf_limited = 1;
        item->tcpinfo->sndbuf_limited = info->result->tcpinfo->sndbuf_limited;
        item->tcpinfo->has_congestion_type = 1;
        item->tcpinfo->congestion_type = info->result->tcpinfo->congestion_type;
    }

    Log(LOG_DEBUG, "tput result: %" PRIu64 " bytes in %" PRIu64 "ms to %s",
        item->bytes, item->duration / (uint64_t) 1000000,
        (item->direction ==
         AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT) ?
        "client" : "server");

    return item;
}



/**
 * Fills memory with random data, much like memset()
 *
 * @param data
 *          A char* to the memory you wish to randomise
 * @param size
 *          The number of bytes (chars) to fill
 */
static void randomMemset(void *data, unsigned int size) {
    int fd;

    if ( (fd = open("/dev/urandom", O_RDONLY)) < 0 ) {
        /* TODO do we want to shut the test down if this fails? */
        Log(LOG_WARNING, "Failed to open /dev/urandom: %s", strerror(errno));
        return;
    }

    read(fd, data, size);
    close(fd);
}



/*
 * Add an HTTP chunk header to the buffer. If we are transmitting data for a
 * set time then we don't know how much data will get sent, so make one chunk
 * per write.
 *
 * The chunk starts with a string of hex digits describing the size of the
 * chunk, followed by CRLF, the data itself, and a terminating CRLF.
 *
 * See https://tools.ietf.org/html/rfc7230#section-4.1
 */
static void addHttpChunkHeader(void *data, unsigned int size, int randomise) {
    /* fill the buffer with random data if required */
    if ( randomise ) {
        randomMemset(data, size);
    }

    /*
     * Figure out how long the size string will be, and subtract its length,
     * the following CRLF and the trailing CLRF from the total length.
     */
    if ( size < 0x5 ) {
        /*
         * Don't do anything, there isn't enough room here. It can just be
         * random data and hopefully no HTTP proxies will mind too much.
         */
        return;
    } else if ( size < 0x10 + 3 + 2 ) {
        sprintf(data, "%x\r\n", size - 3 - 2);
    } else if ( size < 0x100 + 4 + 2 ) {
        sprintf(data, "%x\r\n", size - 4 - 2);
    } else if ( size < 0x10000 + 5 + 2 ) {
        sprintf(data, "%x\r\n", size - 5 - 2);
    } else if ( size < 0x100000 + 6 + 2 ) {
        sprintf(data, "%x\r\n", size - 6 - 2);
    } else if ( size < 0x1000000 + 7 + 2 ) {
        sprintf(data, "%x\r\n", size - 7 - 2);
    } else if ( size < 0x10000000 + 8 + 2 ) {
        sprintf(data, "%x\r\n", size - 8 - 2);
    } else {
        sprintf(data, "%x\r\n", size - 9 - 2);
    }

    /* terminate the chunk with CRLF */
    ((char*)data)[size - 2] = '\r';
    ((char*)data)[size - 1] = '\n';
}



/*
 * Add some typical HTTP headers to the buffer to make it look like an upload.
 */
static void addHttpHeaders(void *data, unsigned int size) {
    char *headers =
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "User-Agent: AMP throughput test agent\r\n"
        "Accept: */*\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n";

    if ( size < strlen(headers) ) {
        Log(LOG_WARNING,
                "Write size %d too small to fit headers in single write (%d)",
                size, strlen(headers));
        return;
    }

    sprintf(data, "%s", headers);

    /* make a chunk out of the remaining space in the buffer */
    if ( size - strlen(headers) > 0 ) {
        addHttpChunkHeader(data + strlen(headers), size - strlen(headers), 1);
    }
}


/*
 * Query the socket for some more in-depth information about the TCP state
 * can specify if waiting till connection is finished sending.
 */
static struct tcpinfo_result_t *get_tcp_info(int sock_fd, int wait_finished) {
    struct tcpinfo_result_t *result;
    struct amp_tcp_info *tcp_info = calloc(1, sizeof(struct amp_tcp_info));
    int tcp_info_len = sizeof(struct amp_tcp_info);
    int attempts = 10;

    do {
        /* get the tcp info block */
        if ( getsockopt(sock_fd, IPPROTO_TCP, TCP_INFO, (void *)tcp_info,
                    (socklen_t *)&tcp_info_len) < 0 ) {
            perror("getsockopt");
            free(tcp_info);
            return NULL;
        }
        /* delay until all bytes have been sent or we've waited long enough */
        attempts--;
    } while ( attempts > 0 && tcp_info->tcpi_notsent_bytes > 0 &&
        wait_finished && usleep(100000) == 0 );
    result = calloc(1, sizeof(struct tcpinfo_result_t));

    /*
    * if the connection isn't app limited then the delivery rate is the most
    * recent value rather than the maximum
    * TODO why isn't it always app limited when we have no data left to send?
    * https://github.com/torvalds/linux/commit/eb8329e0a04db0061f714f033b4454
    * https://github.com/torvalds/linux/commit/b9f64820fb226a4e8ab10591f46cec
    * https://github.com/torvalds/linux/commit/d7722e8570fc0f1e003cee7cf37694
    */
    if ( tcp_info->tcpi_delivery_rate_app_limited ) {
        result->delivery_rate = tcp_info->tcpi_delivery_rate;
    }

    /*
     * Core part of a struct that contains the values we care about don't change
     * or don't exist, so we can read where they could be which will either have
     * the value or be empty, both are valid.
     */

    result->total_retrans = tcp_info->tcpi_total_retrans;
    result->rtt = tcp_info->tcpi_rtt;
    result->rttvar = tcp_info->tcpi_rttvar;
    result->min_rtt = tcp_info->tcpi_min_rtt;
    result->busy_time = tcp_info->tcpi_busy_time;
    result->rwnd_limited = tcp_info->tcpi_rwnd_limited;
    result->sndbuf_limited = tcp_info->tcpi_sndbuf_limited;

    free(tcp_info);

    return result;
}


/*
 * Decision tree classifier created from data set generated by this program
 */
static int classify(float CoV, float NormRange) {
    if ( NormRange <= 0.816066712141037 ) {
        if ( CoV <= 0.09541601315140724 ) {
            return AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__EXTERNAL;
        } else {
            if ( NormRange <= 0.6482022404670715 ) {
                return AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__EXTERNAL;
            } else {
                return AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__SELF;
            }
        }
    } else {
        if ( CoV <= 0.11838533729314804 ) {
            if ( NormRange <= 0.9539760947227478 ) {
                return AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__EXTERNAL;
            } else {
                return AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__SELF;
            }
        } else {
            return AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__SELF;
        }
    }
}



/*
 * Infer the kind of congestion that is occurring from the collected round trip
 * times of the slow start period by calculating the Normalized range
 * and the Coefficient of variation.
 */
static void process_rtt(struct test_result_t *res,
        struct rtt_samples_t *rtt_samples) {

    int32_t mean_sum = 0;
    int32_t min = INT_MAX;
    int32_t max = INT_MIN;
    float mean = 0;
    float sum = 0;
    float NormRange;
    float CoV;


    if ( rtt_samples->rttcount <= 2 ) {
        /*
         * Insufficient records to say what form of congestion,
         * link is too unhealthy to infer congestion reason
         */
        res->tcpinfo->congestion_type =
                AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__UNHEALTHY;
        return;
    } else if ( res->tcpinfo->total_retrans == 0 ) {
        /*
         * somehow managed to not get a single re-transmit,
         * link is too healthy to infer congestion reason
         * (or even if congestion is occurring at all)
         */
        res->tcpinfo->congestion_type =
                AMPLET2__THROUGHPUT__TCPINFO__CONGESTION__TYPE__TOO_HEALTHY;
        return;
    }

    /* Calculate the mean/min/max */
    for ( int i = 0; i < rtt_samples->rttcount; i++ ) {
        mean_sum+= rtt_samples->samples[i];
        if ( rtt_samples->samples[i] > max ) max = rtt_samples->samples[i];
        if ( rtt_samples->samples[i] < min ) min = rtt_samples->samples[i];
    }
    mean = (float)mean_sum / (float)rtt_samples->rttcount;

    /* Calculate std dev */
    for (int i = 0; i < rtt_samples->rttcount; i++ ) {
        sum += ((rtt_samples->samples[i] - mean)*(rtt_samples->samples[i] - mean));
    }
    sum /= (float)rtt_samples->rttcount;

    /* Normalized range of rtt */
    NormRange = (max - min)/(float)max;

    /* Coefficient of variation of rrt */
    CoV = sum/(mean*mean);

    res->tcpinfo->congestion_type = classify(CoV, NormRange);

    /* output dump for training data */
    Log(LOG_DEBUG, "Congestion-Data: CoV:%.10f NormRange:%.10f "
            "RTT:count%d type:%d\n",
            CoV,
            NormRange,
            rtt_samples->rttcount,
            res->tcpinfo->congestion_type);

}


/*
 * Do the actual write and ensure the entire buffer is written.
 *
 * @param sock_fd
 *          The sock to write() to
 * @param data
 *          Pointer to the data buffer to be written.
 * @param length
 *          The length of the data buffer.
 *
 * @return 0 if successful, -1 if failure.
 */
int writeBuffer(int sock_fd, void *data, size_t length,
        struct rtt_samples_t *rtt_samples) {
    int result;
    size_t total_written = 0;

    do {
        result = write(sock_fd, data + total_written, length - total_written);

        if ( rtt_samples->keep_recording ) {
            struct tcpinfo_result_t* tcpi = get_tcp_info(sock_fd, 0);

            if ( (tcpi->total_retrans != 0) ||
                    (rtt_samples->rttcount >= MAXSAMPLES) ) {
                rtt_samples->keep_recording = 0;
            }
            rtt_samples->samples[rtt_samples->rttcount] = tcpi->rtt;
            rtt_samples->rttcount++;
            free(tcpi);
        }

        if ( result > 0 ) {
            total_written += result;
        }

        /*
         * Keep trying to write until we have sent everything we have or we
         * get a real error. An interrupted write that has sent data won't
         * give an EINTR, it will just return less than the full number of
         * bytes it was meant to send.
         */
    } while ( (result > 0 && total_written < length) ||
                    ( result < 0 && errno == EINTR ) );

    if ( total_written != length ) {
        Log(LOG_WARNING, "write return %d, total %d (not %d): %s\n", result,
                total_written, length, strerror(errno));
        return -1;
    }

/*
    Log(LOG_DEBUG, "successfully sent %d of %d bytes", total_written,
            total_size);
*/
    return total_written;
}



/*
 * Read and discard some test data.
 */
int readBuffer(int test_socket) {
    int result;
    char buf[DEFAULT_WRITE_SIZE];

    do {
        result = read(test_socket, buf, sizeof(buf));
    } while ( result < 0 && errno == EINTR );

    if ( result < 0 ) {
        Log(LOG_WARNING, "Error receiving TCP throughput data: %s\n",
                strerror(errno));
    }

    return result;
}



/**
 * Send data over the given socket i.e. do an outgoing tput test.
 * Based upon test options, if test options are invalid no packets
 * are sent (such as no terminating condition, 0 packet size etc).
 *
 * @param sock_fd
 *          The socket to send data across
 * @param test_opts
 *          A item from the test schedule with all the details
 *          for this test
 * @param res
 *          The result of this test, cannot be NULL.
 *
 * @return 0 success, 1 if bad test supplied, -1 if socket error
 */
int sendStream(int sock_fd, struct test_request_t *test_opts,
        struct test_result_t *res) {

    int more;
    uint64_t run_time_ms;
    void *packet_out;
    int32_t bytes_sent = 0;
    uint32_t bytes_to_send;
    struct timeval timeout;
    int result;
    fd_set write_set;

    struct rtt_samples_t *rtt_samples = calloc(1, sizeof(struct rtt_samples_t));
    rtt_samples->rttcount = 0;
    rtt_samples->keep_recording = 1;

    /* Make sure the test is valid */
    if ( test_opts->bytes == 0 && test_opts->duration == 0 ) {
        Log(LOG_ERR, "no terminating condition for test");
        return -1;
    }

    /* Log the stopping condition */
    if ( test_opts->bytes > 0 ) {
        Log(LOG_DEBUG, "Sending %d bytes\n", test_opts->bytes);
    }
    if ( test_opts->duration > 0 ) {
        Log(LOG_DEBUG, "Sending for %ldms\n", test_opts->duration);
    }

    /* Build our packet */
    packet_out = calloc(1, test_opts->write_size);
    if ( packet_out == NULL ) {
        Log(LOG_ERR, "sendStream() malloc failed : %s\n", strerror(errno));
        return -1;
    }

    /* Note starting time */
    run_time_ms = 0;
    res->start_ns = timeNanoseconds();
    more = 1;

    do {
        res->end_ns = timeNanoseconds();
        run_time_ms = (res->end_ns - res->start_ns) / 1e6;

        /* timeout should be remaining duration of the test (if set) */
        if ( test_opts->duration > 0 ) {
            if ( run_time_ms >= test_opts->duration ) {
                break;
            }
            /* run time is being measured in ms, so measure timeout the same */
            timeout.tv_sec = (test_opts->duration - run_time_ms) / 1000;
            timeout.tv_usec = (test_opts->duration - run_time_ms) % 1000 * 1000;
        } else {
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;
        }

        /* amount of data to send should be remaining data (if set) */
        if ( test_opts->bytes > 0 &&
                test_opts->bytes - res->bytes < test_opts->write_size) {
            bytes_to_send = test_opts->bytes - res->bytes;
            more = 0;
        } else {
            bytes_to_send = test_opts->write_size;
        }

        FD_ZERO(&write_set);
        FD_SET(sock_fd, &write_set);

        result = select(sock_fd + 1, NULL, &write_set, NULL, &timeout);

        /* timeout has fired, stop the test */
        if ( result == 0 ) {
            break;
        }

        /* error, check if we can carry on or need to stop the test */
        if ( result < 0 ) {
            if ( errno == EINTR ) {
                continue;
            } else {
                Log(LOG_WARNING, "Error sending TCP throughput data: %s\n",
                        strerror(errno));
                break;
            }
        }

        /* we can write to the test socket, do so */
        if ( FD_ISSET(sock_fd, &write_set) ) {
            if ( test_opts->protocol == TPUT_PROTOCOL_HTTP_POST ) {
                if ( res->bytes == 0 ) {
                    /* start with an HTTP header to get proxies interested */
                    addHttpHeaders(packet_out, bytes_to_send);
                } else {
                    addHttpChunkHeader(packet_out, bytes_to_send,
                            test_opts->randomise);
                }
            } else if ( test_opts->randomise || res->bytes == 0 ) {
                /* randomise the first packet, or every packet if option set */
                randomMemset(packet_out, bytes_to_send);
            }

            /* send the data */
            if ( (bytes_sent = writeBuffer(sock_fd, packet_out,
                            bytes_to_send, rtt_samples)) < 0 ) {
                Log(LOG_ERR, "sendStream() could not send data packet\n");
                break;
            }

            res->bytes += bytes_sent;
        }
    } while ( more );

    res->end_ns = timeNanoseconds();
    res->tcpinfo = get_tcp_info(sock_fd, 1);
    process_rtt(res, rtt_samples);

    free(packet_out);
    free(rtt_samples);
    return 0;
}



/**
 * Receive an incoming test and record our result in result
 *
 * @param sock_fd
 *          The socket we expect to see the DATA packets on
 * @param req
 *          The test request to log results against
 * @param options
 *          The global test options
 *
 * @return 0 upon success otherwise -1
 */
int incomingTest(int sock_fd, struct test_result_t *result) {
    int bytes_read;

    memset(result, 0, sizeof(struct test_result_t));

    while ( (bytes_read = readBuffer(sock_fd)) > 0 ) {
        /* The first data packet is the indicator the test has started */
        if ( result->bytes == 0 ) {
            Log(LOG_DEBUG, "Received first packet from incoming test");
            result->start_ns = timeNanoseconds();
        }
        result->bytes += bytes_read;
    }

    /* No more packets to be received means we should send our results */
    if ( result->bytes > 0 ) {
        result->end_ns = timeNanoseconds();
    }

    return 0;
}



/**
 * Currently not nanosecond resolution but will give a resulting time in
 * mutiplied to nanoseconds.
 */
uint64_t timeNanoseconds(void){
    /* TODO see if clock_gettime() can be used for a truly high resolution */
    struct timeval t = {0, 0};
    gettimeofday(&t, NULL);
    return (uint64_t) t.tv_sec * (uint64_t) 1000000000 +
        (uint64_t) t.tv_usec * (uint64_t) 1000;
}
