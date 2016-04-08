/**
 * Common functions used by both the throughtput client and
 * server
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "throughput.h"
#include "serverlib.h"
#include "debug.h"



/*
 *
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

    data->len = amplet2__throughput__hello__get_packed_size(&hello);
    data->data = malloc(data->len);
    amplet2__throughput__hello__pack(&hello, data->data);

    return data;
}



/*
 *
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

    amplet2__throughput__hello__free_unpacked(hello, NULL);

    return options;
}



/*
 *
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
 *
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
 *
 */
Amplet2__Throughput__Item* report_schedule(struct test_request_t *info) {

    Amplet2__Throughput__Item *item =
        (Amplet2__Throughput__Item*)malloc(sizeof(Amplet2__Throughput__Item));
    struct test_result_t *result;

    /* Get the result from the receiving side */
    result = (info->type == TPUT_2_CLIENT) ? info->c_result : info->s_result;

    /* fill the report item with results of a test */
    amplet2__throughput__item__init(item);
    item->has_direction = 1;
    item->direction = info->type;
    item->has_duration = 1;
    item->duration = result->end_ns - result->start_ns;
    item->has_bytes = 1;
    item->bytes = result->bytes;

#if 0
    item->has_web10g_client = info->c_web10g ? 1 : 0;
    item->has_web10g_server = info->s_web10g ? 1 : 0;

    if ( item->c_web10g ) {
    }

    if ( item->s_web10g ) {
    }
#endif

    Log(LOG_DEBUG, "tput result: %" PRIu64 " bytes in %" PRIu64 "ms to %s",
        item->bytes, item->duration / (uint64_t) 1000000,
        (item->direction ==
         AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT) ?
        "client" : "server");

    return item;
}



/**
 * Converts a valid packet format from host to big endian ready for
 * the network
 *
 * @param p
 *          A pointer to the packet to convert
 */
static void htobePacket(struct packet_t *p) {
    switch ( p->header.type ) {
        case TPUT_PKT_DATA:
            p->types.data.more = htobe32(p->types.data.more);
            break;
        default:
            Log(LOG_WARNING, "Bad packet type found cannot decode!!!");
    }
    p->header.type = htobe32(p->header.type);
    p->header.size = htobe32(p->header.size);
}



/**
 * Converts a valid packet from the network to host endianness
 *
 * @param p
 *          A pointer to the packet to convert
 */
static void betohPacket(struct packet_t *p) {
    p->header.type = be32toh(p->header.type);
    p->header.size = be32toh(p->header.size);
    switch ( p->header.type ) {
        case TPUT_PKT_DATA:
            p->types.data.more = be32toh(p->types.data.more);
            break;
        default:
            Log(LOG_WARNING, "Bad packet type found cannot decode!!!");
    }
}



/**
 * Fills memory with random data, much like memset()
 *
 * @param data
 *          A char* to the memory you wish to randomise
 * @param size
 *          The number of bytes (chars) to fill
 */
static void randomMemset(char *data, unsigned int size){
    int fd;

    if ( (fd = open("/dev/urandom", O_RDONLY)) < 0 ) {
        /* TODO do we want to shut the test down if this fails? */
        Log(LOG_WARNING, "Failed to open /dev/urandom: %s", strerror(errno));
        return;
    }

    read(fd, data, size);
    close(fd);
}



/**
 * Do the actual write and ensure the entire packet is written.
 * This handles conversion of the packet to Big Endian before sending.
 * The packet will be returned unchanged
 *                          (i.e. converted back to host byte order).
 *
 * @param sock_fd
 *          The sock to write() to
 * @param packet
 *          The packet to write, returned unchanged. Size must be correct.
 *
 * @return 0 if successful, -1 if failure.
 */
int writePacket(int sock_fd, struct packet_t *packet){
    int res;
    int total_written = 0;
    int total_size = packet->header.size + sizeof(struct packet_t);

/*
    Log(LOG_DEBUG, "Sending packet of type %d with size %d",
            packet->header.type, total_size);
*/
    /* Convert to big endian */
    htobePacket(packet);

    do {
        res = write(sock_fd, (void*)packet+total_written,
                total_size-total_written);

        if ( res > 0 ) {
            total_written += res;
            /*Log(LOG_DEBUG, "wrote %d, now at %d of %d bytes",
                res, total_written, total_size);*/
        }

        /*
         * Keep trying to write until we have sent everything we have or we
         * get a real error. An interrupted write that has sent data won't
         * give an EINTR, it will just return less than the full number of
         * bytes it was meant to send.
         */
    } while ( (res > 0 && total_written < total_size) ||
                    ( res < 0 && errno == EINTR ) );

    /* Convert back to host, we don't actually want to change the packet */
    betohPacket(packet);

    if ( total_written != total_size ) {
        Log(LOG_WARNING, "write return %d, total %d (not %d): %s\n", res,
                total_written, total_size, strerror(errno));
        return -1;
    }

/*
    Log(LOG_DEBUG, "successfully sent %d of %d bytes", total_written,
            total_size);
*/
    return total_written;
}



/**
 * Read() in a packet_t
 * Recevies the header
 * Dumps any additional data, unless given additional in which case
 * a malloc'd memory block will be returned.
 *
 * @param test_socket
 *          The socket to read from
 * @param packet
 *          To put result into
 * @param addtional
 *          Will place a malloc'd block of memory here with any extra
 *          data (beyond the header).
 *          If packet.header.size is 0 this is set to NULL.
 * @return the number of bytes read, 0 is used to indicate a failure.
 *         A failure includes a socket error, early packet termination
 *         and EOF reached before reading any packet.
 */
int readPacket(int test_socket, struct packet_t *packet, char **additional) {
    int result;
    uint32_t bytes_read;
    char buf[DEFAULT_WRITE_SIZE];

    bytes_read = 0;

    /* Read in the packet_t first, so we can get the packet size */
    do {
        /*
        Log(LOG_DEBUG, "DOING READ %" PRIu32 " %d", bytes_read,
                sizeof(struct packet_t));
        */
        result = read(test_socket, ((uint8_t *) packet) + bytes_read,
                sizeof(struct packet_t) - bytes_read);

        if ( result == -1 && errno == EINTR ) {
            continue;
        }
        if ( result == -1 ) {
            Log(LOG_WARNING, "read() on socket failed : %s" , strerror(errno));
            return 0;
        }
        if ( result == 0 ) {
            /* EOF */
            return 0;
        }
        /* increase the read_count */
        bytes_read += result;
    } while ( bytes_read < sizeof(struct packet_t));

    /* Fix endianness */
    betohPacket(packet);

    /* packet->header.size excludes it's own size */
    bytes_read = 0;

    if ( additional ) {
        if ( packet->header.size > 0 && packet->header.size < MAX_MALLOC ) {
            *additional = malloc(packet->header.size);
        } else {
            *additional = NULL;
        }
    }

    /* Dump out the rest of the packet */
    while ( bytes_read < packet->header.size ) {
        if ( additional == NULL || *additional == NULL ) {
            /* Throw away */
            result = read(test_socket, buf,
                     MIN(packet->header.size-bytes_read, sizeof(buf)));
        } else {
            /* Store in our buffer */
            result = read(test_socket, *additional + bytes_read,
                                        packet->header.size-bytes_read);
        }

        if ( result == -1 && errno == EINTR ) {
            continue;
        }
        if ( result == -1 ) {
            Log(LOG_WARNING, "read() on socket failed : %s" , strerror(errno));
            return 0;
        }
        if ( result == 0 ) {
            Log(LOG_WARNING,
                    "EOF found before the end of the packet additional data");
            return 0;
        }
        bytes_read += result;
    }

    /* return will be above 0 if successful - 0 indicates failure */
    return bytes_read + sizeof(struct packet_t);
}



/**
 * Send Packets over the given socket i.e. do an outgoing tput test.
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
int sendPackets(int sock_fd, struct test_request_t *test_opts,
                struct test_result_t *res) {

    int more; /* Still got more to send ? */
    uint64_t run_time_ms;
    struct packet_t *packet_out; /* the packet header and data */
    int32_t bytes_sent = 0;

    /* Make sure the test is valid */
    if ( test_opts->bytes == 0 && test_opts->duration == 0 ) {
        Log(LOG_ERR, "no terminating condition for test");
        return 1;
    }

    /* Log the stopping condition */
    if ( test_opts->bytes > 0 ) {
        Log(LOG_DEBUG, "Sending %d bytes\n", test_opts->bytes);
    }
    if ( test_opts->duration > 0 ) {
        Log(LOG_DEBUG, "Sending for %ldms\n", test_opts->duration);
    }

    /* Build our packet */
    packet_out = (struct packet_t *) malloc(test_opts->write_size);
    if ( packet_out == NULL ) {
        Log(LOG_ERR, "sendPackets() malloc failed : %s\n", strerror(errno));
        return 1;
    }
    memset(packet_out, 0, sizeof(struct packet_t));
    packet_out->header.type = TPUT_PKT_DATA;
    packet_out->header.size = test_opts->write_size - sizeof(struct packet_t);
    packet_out->types.data.more = 1;

    /* Note starting time */
    run_time_ms = 0;
    res->start_ns = timeNanoseconds();
    more = 1;

    while ( more ) {
        res->end_ns = timeNanoseconds();
        run_time_ms = (res->end_ns - res->start_ns) / 1e6;
        /* Log(LOG_DEBUG, "runtime = %ld/%ld", run_time_ms,
                        test_opts->duration); */

        /* Randomise the first packet, possibly every packet if option set */
        if ( test_opts->randomise || res->bytes == 0 ) {
            randomMemset((char *)(packet_out+1), packet_out->header.size);
        }

        /* Check if we have meet our exit condition */
        if ( (test_opts->bytes != 0 &&
                    test_opts->bytes - res->bytes < test_opts->write_size) ) {
            /* send the smaller remaining portion and mark end of data */
            packet_out->header.size = test_opts->bytes - res->bytes -
                sizeof(struct packet_t);
            more = 0;

        } else if ( test_opts->duration != 0 &&
                run_time_ms >= test_opts->duration) {
            /* mark end of data, we have reached our time limit */
            more = 0;
        }

        packet_out->types.data.more = more;

        if ( (bytes_sent = writePacket(sock_fd, packet_out)) < 0 ) {
            Log(LOG_ERR, "sendPackets() could not send data packet\n");
            free(packet_out);
            return -1;
        }

        res->bytes += bytes_sent;
    }

    res->end_ns = timeNanoseconds();
    free(packet_out);
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
    struct packet_t packet;
    int bytes_read;

    memset(&packet, 0, sizeof(packet));
    memset(result, 0, sizeof(struct test_result_t));

    while ( (bytes_read = readPacket(sock_fd, &packet, NULL)) != 0 ) {
        switch ( packet.header.type ) {
            case TPUT_PKT_DATA:
                if ( readDataPacket(&packet, bytes_read, result) != 0 ) {
                    /* Error */
                    return -1;
                }
                if ( result->done ) {
                    /* Log() our result */
                    Log(LOG_DEBUG, "incomingTest() Got result from myself "
                                    "%"PRIu32" %"PRIu32" %"PRIu64" %"PRIu64,
                                    result->packets,
                                    result->write_size,
                                    result->end_ns - result->start_ns,
                                    result->bytes);
                    return 0;
                }
                break;
            default:
                Log(LOG_WARNING,
                        "incomingTest() found an unexpected packet type %d",
                        packet.header.type);
        }
    }
    /* Failed to read packet */
    return -1;
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



/**
 * Opposite of sendPackets(), used to interpret incoming DATA packets.
 *
 * @param packet
 *          A packet previously received
 * @param write_size
 *          The size of the packet returned by readPacket()
 * @param res
 *          A test result structure to store this result into, keeps the
 *          track of the test state. Reuse the same res structure.
 *
 * @return 0 upon success, -1 if an error occurs like an unexpected packet type.
 */
int readDataPacket(const struct packet_t *packet, const int write_size,
                                    struct test_result_t *res) {
    if ( packet->header.type != TPUT_PKT_DATA ) {
        return -1;
    }

    if ( res->done ) {
        /* Should always wipe the result for the next test */
        Log(LOG_ERR, "readDataPacket() is using a finished test result.");
        return -1;
    }

    /* The first data packet is the indicator the test has started */
    if ( res->packets == 0 ) {
        Log(LOG_DEBUG, "Received first packet from incoming test");
        res->start_ns = timeNanoseconds();
        res->write_size = write_size;
    }

    res->packets++;
    res->bytes += write_size;

    if ( !packet->types.data.more ) {
        /* No more packets to be received means we should send our results */
        res->done = 1;
        res->end_ns = timeNanoseconds();
    }

    return 0;
}
