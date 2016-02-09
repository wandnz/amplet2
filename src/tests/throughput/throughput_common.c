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

#include "throughput.h"
#include "config.h"



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
        case TPUT_PKT_SEND:
            p->types.send.bytes = htobe64(p->types.send.bytes);
            p->types.send.write_size = htobe32(p->types.send.write_size);
            p->types.send.duration_ms = htobe64(p->types.send.duration_ms);
            break;
        case TPUT_PKT_RESULT:
            p->types.result.packets = htobe32(p->types.result.packets);
            p->types.result.write_size = htobe32(p->types.result.write_size);
            p->types.result.bytes = htobe64(p->types.result.bytes);
            p->types.result.duration_ns = htobe64(p->types.result.duration_ns);
            break;
        case TPUT_PKT_HELLO:
            p->types.hello.version = htobe32(p->types.hello.version);
            p->types.hello.mss = htobe32(p->types.hello.mss);
            p->types.hello.sock_rcvbuf = htobe32(p->types.hello.sock_rcvbuf);
            p->types.hello.sock_sndbuf = htobe32(p->types.hello.sock_sndbuf);
            p->types.hello.tport = htobe16(p->types.hello.tport);
            break;
        case TPUT_PKT_READY:
            p->types.ready.tport = htobe16(p->types.ready.tport);
            break;
        case TPUT_PKT_CLOSE:
        case TPUT_PKT_RENEW_CONNECTION:
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
        case TPUT_PKT_SEND:
            p->types.send.bytes = be64toh(p->types.send.bytes);
            p->types.send.write_size = be32toh(p->types.send.write_size);
            p->types.send.duration_ms = be64toh(p->types.send.duration_ms);
            break;
        case TPUT_PKT_RESULT:
            p->types.result.packets = be32toh(p->types.result.packets);
            p->types.result.write_size = be32toh(p->types.result.write_size);
            p->types.result.bytes = be64toh(p->types.result.bytes);
            p->types.result.duration_ns = be64toh(p->types.result.duration_ns);
            break;
        case TPUT_PKT_HELLO:
            p->types.hello.version = be32toh(p->types.hello.version);
            p->types.hello.mss = be32toh(p->types.hello.mss);
            p->types.hello.sock_rcvbuf = be32toh(p->types.hello.sock_rcvbuf);
            p->types.hello.sock_sndbuf = be32toh(p->types.hello.sock_sndbuf);
            p->types.hello.tport = be16toh(p->types.hello.tport);
            break;
        case TPUT_PKT_READY:
            p->types.ready.tport = be16toh(p->types.ready.tport);
            break;
        case TPUT_PKT_CLOSE:
        case TPUT_PKT_RENEW_CONNECTION:
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
 * Calls setsockopt() then returns getsockopt() to verify the change
 * This will Log() errors if they occur.
 *
 * @param sock_fd
 *          The socket file descriptor
 * @param newValue
 *          The value to set it to. Upon return this conatians the value
 *          from getsockopt(). Undefined upon return if this results in
 *          failure.
 * @param proto
 *          The protocol to apply this to IPPROTO_TCP etc.
 * @param opt
 *          The option to set TCP_MAXSEG etc.
 * @param optname
 *          A textural representation of the sock name printed in errors
 *
 * @param return 0 if success - otherwise -1
 */
static int setVerifySockopt(int sock_fd, int *newValue, int proto,
        int opt, const char *optname) {
    socklen_t newValueSize;
    int ret;

    newValueSize = sizeof(newValue);
    ret = setsockopt(sock_fd, proto, opt, newValue, newValueSize);
    if ( ret != 0 ) {
        Log(LOG_WARNING, "setsockopt failed to set the %s option to %d: %s",
                optname,  *newValue, strerror(errno));
        return -1;
    }

    /* Verify */
    *newValue = 0;
    ret = getsockopt(sock_fd, proto, opt, newValue, &newValueSize);
    if ( ret != 0 ) {
        Log(LOG_WARNING, "getsockopt failed to get the %s option: %s",
                optname, strerror(errno));
        return -1;
    }

    /* Success */
    return 0;
}



/**
 * Tries to set the relevent socket options given in the opt_t structure
 * for if the value is 0 we ignore it.
 *
 * @param options
 *          An option structure with containing the options to set.
 *          Can be NULL.
 * @param sock_fd
 *          The socket file descriptor to apply this to.
 */
void doSocketSetup(struct opt_t *options, int sock_fd){
    int ret;
    int newValue;

    if ( options == NULL ) {
        return;
    }

    /* set TCP_MAXSEG option */
    if ( options->sock_mss > 0 ) {
#ifdef TCP_MAXSEG
        newValue = options->sock_mss;
        ret = setVerifySockopt(sock_fd, &newValue, IPPROTO_TCP,
                TCP_MAXSEG, "TCP_MAXSEG");

        if ( ret == 0 && newValue != options->sock_mss ) {
            Log(LOG_WARNING, "setsockopt succeeded however getsockopt"
                                " doesn't agree - wanted TCP_MAXSEG set"
                                " :%" PRId32 " but got :%d",
                                options->sock_mss, newValue);
            /* TODO SHOULD set max mss to what we really used for reporting?? */
        }
        Log(LOG_DEBUG, "setsockopt set TCP_MAXSEG to %d", newValue);
#else
        Log(LOG_WARNING, "Requested to set sock_mss, but this build"
                " doesn't have TCP_MAXSEG defined");
#endif
    }

    /* set TCP_NODELAY option */
    if ( options->sock_disable_nagle ) {
#ifdef TCP_NODELAY
        newValue = 1;
        ret = setVerifySockopt(sock_fd, &newValue, IPPROTO_TCP,
                TCP_NODELAY, "TCP_NODELAY");
        if ( ret == 0 && newValue == 0 ) {
            Log(LOG_WARNING, "setsockopt succeeded disabling nagle"
                    " however getsockopt still says its enabled");
        }

        Log(LOG_DEBUG, "setsockopt set TCP_NODELAY to %d", newValue);

#else
        Log(LOG_WARNING, "Requested to disable nagle, but this build"
                " doesn't have TCP_NODELAY defined");
#endif
    }

    /* set SO_RCVBUF option */
    if ( options->sock_rcvbuf > 0 ) {
#ifdef SO_RCVBUF
        newValue = options->sock_rcvbuf;
        ret = setVerifySockopt(sock_fd, &newValue, SOL_SOCKET,
                SO_RCVBUF, "SO_RCVBUF");
        if ( ret == 0 && newValue / 2 != options->sock_rcvbuf ) {
            Log(LOG_WARNING, "setsockopt succeeded however getsockopt"
                    " doesn't agree - wanted SO_RCVBUF set"
                    " :%" PRId32 " but got :%d",
                    options->sock_rcvbuf, newValue);
        }
        Log(LOG_DEBUG, "setsockopt set SO_RCVBUF to %d", newValue);

#ifdef SO_RCVBUFFORCE
        /* Like SO_RCVBUF but if user has CAP_ADMIN privilage ignores
         * /proc/max size */
        if ( ret == -1 || newValue / 2 != options->sock_rcvbuf ) {
            newValue = options->sock_rcvbuf;
            ret = setVerifySockopt(sock_fd, &newValue, SOL_SOCKET,
                    SO_RCVBUFFORCE, "SO_RCVBUFFORCE");
            if ( ret == 0 && newValue / 2 != options->sock_rcvbuf ) {
                Log(LOG_WARNING, "setsockopt succeeded however"
                        " getsockopt doesn't agree - wanted "
                        "SO_RCVBUFFORCE set :%" PRId32 " but got :%d",
                        options->sock_rcvbuf, newValue);
            }
        }
#endif /* SO_RCVBUFFORCE */

#else
        Log(LOG_WARNING, "Requested to set max receive buffer, but this"
                " build doesn't have SO_RCVBUF defined");
#endif /* SO_RCVBUF */
    }

    /* set SO_SNDBUF option */
    if ( options->sock_sndbuf > 0 ) {
#ifdef SO_SNDBUF
        newValue = options->sock_sndbuf;
        ret = setVerifySockopt(sock_fd, &newValue, SOL_SOCKET,
                SO_SNDBUF, "SO_SNDBUF");
        if ( ret == 0 && newValue / 2 != options->sock_sndbuf ) {
            Log(LOG_WARNING, "setsockopt succeeded however getsockopt "
                    "doesn't agree - wanted SO_SNDBUF set "
                    ":%" PRId32 " but got :%d",
                    options->sock_sndbuf, newValue);
        }

        Log(LOG_DEBUG, "setsockopt set SO_SNDBUF to %d", newValue);
#ifdef SO_SNDBUFFORCE
        /* Like SO_RCVBUF but if user has CAP_ADMIN privilage ignores
         * /proc/max size */
        if ( ret == -1 || newValue / 2 != options->sock_sndbuf ) {
            newValue = options->sock_sndbuf;
            ret = setVerifySockopt(sock_fd, &newValue, SOL_SOCKET,
                                    SO_SNDBUFFORCE, "SO_SNDBUFFORCE");
            if ( ret == 0 && newValue / 2 != options->sock_sndbuf ) {
                Log(LOG_WARNING, "setsockopt succeeded however"
                        " getsockopt doesn't agree - wanted "
                        "SO_SNDBUFFORCE set :%" PRId32 " but got :%d",
                        options->sock_sndbuf, newValue);

            }
        }
#endif /* SO_SNDBUFFORCE */

#else
        Log(LOG_WARNING, "Requested to set max send buffer, but this"
                " build doesn't have SO_SNDBUF defined");
#endif /* SO_SNDBUF */
    }

    /* set SO_REUSEADDR option */
    if (options->reuse_addr ) {
#ifdef SO_REUSEADDR
        newValue = 1;
        ret = setVerifySockopt(sock_fd, &newValue, SOL_SOCKET,
                SO_REUSEADDR, "SO_REUSEADDR");
        if ( ret == 0 && newValue == 0 ) {
            Log(LOG_WARNING, "setsockopt succeeded in setting SO_REUSEADDR"
                    " however getsockopt still says its enabled");
        }
        Log(LOG_DEBUG, "setsockopt set SO_REUSEADDR to %d", newValue);
#else
        Log(LOG_WARNING, "Requested to reuse address, but this build"
                " doesn't have SO_REUSEADDR defined");
#endif
    }
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



/**
 * Constructs and sends a result packet
 *
 * @param result
 *          A structure holding the results to send
 * @param web10g
 *         Can be NULL. The web10g result.
 *
 * @return The result of writePacket() - NOTE : The packet will always
 *         construct successfully.
 */
int sendResultPacket(int sock_fd, struct test_result_t *res,
        struct report_web10g_t *web10g){
    struct packet_t p;
    struct packet_t *p_web10g;
    int ret;

    memset(&p, 0, sizeof(p));
    p.header.type = TPUT_PKT_RESULT;
    p.header.size = ( web10g == NULL ? 0 : sizeof(struct report_web10g_t) );
    p.types.result.bytes = res->bytes;
    p.types.result.duration_ns = res->end_ns - res->start_ns;
    p.types.result.write_size = res->write_size;
    p.types.result.packets = res->packets;

    if ( web10g == NULL ) {
        /* Nothing extra */
        p.header.size = 0;
        return writePacket(sock_fd, &p);
    }

    /* Concatenate the packet and the web10g data then send */
    p_web10g = malloc(sizeof(struct packet_t) + sizeof(struct report_web10g_t));

    p.header.size = sizeof(struct report_web10g_t);
    memcpy(p_web10g, &p, sizeof(struct packet_t));
    memcpy(p_web10g + 1, web10g, sizeof(struct report_web10g_t));

    ret = writePacket(sock_fd, p_web10g);

    free(p_web10g);
    return ret;
}



/**
 * Constructs and sends a reset packet
 *
 * @param sock_fd
 *         The socket to write() the packet to
 *
 * @return The result of writePacket()
 */
int sendResetPacket(int sock_fd) {
    struct packet_t p;
    memset(&p, 0, sizeof(p));
    p.header.type = TPUT_PKT_RENEW_CONNECTION;
    p.header.size = 0;

    return writePacket(sock_fd, &p);
}



/**
 * Constructs and sends a final (i.e. more = 0) data packet.
 *
 * @param sock_fd
 *          The socket to write() the packet to
 *
 * @return The result of writePacket()
 */
int sendFinalDataPacket(int sock_fd) {
    struct packet_t p;
    memset(&p, 0, sizeof(p));
    p.header.type = TPUT_PKT_DATA;
    p.header.size = 0;
    p.types.data.more = 0;

    return writePacket(sock_fd, &p);
}



/**
 * Constructs and sends a reset packet
 *
 * @param sock_fd
 *          The socket to write() the packet to
 * @param disable_web10g
 *          Disable web10g results if != 0
 *
 * @return The result of writePacket() - NOTE : The packet will always
 *         construct successfully.
 */
int sendHelloPacket(int sock_fd, struct opt_t *opt) {
    struct packet_t p;
    memset(&p, 0, sizeof(p));
    p.header.type = TPUT_PKT_HELLO;
    p.header.size = 0;
    p.types.hello.version = AMP_THROUGHPUT_TEST_VERSION;

    /* Flags Only 1 byte of these */
    if ( opt->sock_disable_nagle ) {
        p.types.hello.flags |= TPUT_PKT_FLAG_NO_NAGLE;
    }
    if ( opt->disable_web10g ) {
        p.types.hello.flags |= TPUT_PKT_FLAG_NO_WEB10G;
    }
    if ( opt->randomise ) {
        p.types.hello.flags |= TPUT_PKT_FLAG_RANDOMISE;
    }

    p.types.hello.tport = opt->tport;
    p.types.hello.mss = opt->sock_mss;
    p.types.hello.sock_rcvbuf = opt->sock_rcvbuf;
    p.types.hello.sock_sndbuf = opt->sock_sndbuf;

    return writePacket(sock_fd, &p);
}



/**
 * Constructs and sends a close packet
 *
 * @param sock_fd
 *          The socket to write() the packet to
 *
 * @return The result of writePacket() - NOTE : The packet will always
 *         construct successfully.
 */
int sendClosePacket(int sock_fd) {
    struct packet_t p;
    memset(&p, 0, sizeof(p));
    p.header.type = TPUT_PKT_CLOSE;
    p.header.size = 0;
    return writePacket(sock_fd, &p);
}



/**
 * Constructs and sends a ready packet
 *
 * @param sock_fd
 *          The socket to write() the packet to
 * @param tport
 *          The successfully connected tport number.
 *
 * @return The result of writePacket() - NOTE : The packet will always
 *         construct successfully.
 */
int sendReadyPacket(int sock_fd, uint16_t tport) {
    struct packet_t p;
    memset(&p, 0, sizeof(p));
    p.header.type = TPUT_PKT_READY;
    p.header.size = 0;
    p.types.ready.tport = tport;
    return writePacket(sock_fd, &p);
}



/**
 * Constructs and sends a SEND packet.
 *
 * @param sock_fd
 *              The socket to send the packet to
 * @param req
 *              A structure containing the test details
 *
 * @return The result of writePacket()
 */
int sendRequestTestPacket(int sock, const struct test_request_t *req) {
    struct packet_t p;

    memset(&p, 0 , sizeof(p));
    p.header.type = TPUT_PKT_SEND;
    p.header.size = 0;
    p.types.send.duration_ms = req->duration;
    p.types.send.write_size = req->write_size;
    p.types.send.bytes = req->bytes;

    Log(LOG_DEBUG, "Sending a TPUT_PKT_SEND request - "
            "bytes: %d duration: %d write_size: %d",
            p.types.send.bytes, p.types.send.duration_ms,
            p.types.send.write_size);

    return writePacket(sock, &p);
}



/**
 * Given a result packet unpacks into a test_result_t structure
 *
 * @param p
 *          The previously read packet, from readPacket()
 * @param res
 *          A structure to unpack the packet into
 *
 * @return 0 upon success, -1 upon failure such as a invalid type
 */
int readResultPacket(const struct packet_t *p, struct test_result_t *res) {
    if ( p->header.type != TPUT_PKT_RESULT ) {
        Log(LOG_ERR, "Required a result packet but type %d instead",
                p->header.type);
        return -1;
    }

    res->done = 1;
    res->bytes = p->types.result.bytes;
    res->write_size = p->types.result.write_size;
    res->packets = p->types.result.packets;
    res->start_ns = 0;
    res->end_ns = p->types.result.duration_ns;

    return 0;
}



/**
 * Constructs and sends a ready packet
 *
 * @param sock_fd
 *          The socket to write() the packet to
 * @param tport
 *          The successfully connected tport number.
 * @return 0 upon success, -1 upon failure such as a invalid type
 */
int readReadyPacket(const struct packet_t *p, uint16_t *tport) {
    if ( p->header.type != TPUT_PKT_READY ) {
        Log(LOG_ERR, "Required a ready packet but type %d instead",
                p->header.type);
        return -1;
    }
    *tport = p->types.ready.tport;
    return 0;
}



/**
 * Given a hello packet unpacks into a test_result_t structure
 *
 * @param p
 *          The previously read packet, from readPacket()
 * @param disable_web10g
 *          Set from packet
 * @param version
 *          Set from packet
 *
 * @return 0 upon success, -1 upon failure such as a invalid type
 */
int readHelloPacket(const struct packet_t *p, struct temp_sockopt_t_xxx *sockopts,
        uint32_t *version) {

    if ( p->header.type != TPUT_PKT_HELLO ) {
        Log(LOG_ERR, "Required a hello packet but type %d instead",
                p->header.type);
        return -1;
    }

    sockopts->tport = p->types.hello.tport;
    sockopts->sock_mss = p->types.hello.mss;
    sockopts->sock_rcvbuf = p->types.hello.sock_rcvbuf;
    sockopts->sock_sndbuf = p->types.hello.sock_sndbuf;

    if ( p->types.hello.flags & TPUT_PKT_FLAG_NO_NAGLE ) {
        sockopts->sock_disable_nagle = 1;
    }
    if ( p->types.hello.flags & TPUT_PKT_FLAG_NO_WEB10G ) {
        sockopts->disable_web10g = 1;
    }
    if ( p->types.hello.flags & TPUT_PKT_FLAG_RANDOMISE ) {
        sockopts->randomise = 1;
    }

    *version = p->types.hello.version;
    return 0;
}
