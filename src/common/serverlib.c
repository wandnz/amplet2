#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/tcp.h>

#include <amqp.h>
#include <amqp_framing.h>

#include <google/protobuf-c/protobuf-c.h>

#include "testlib.h"
#include "debug.h"
#include "tests.h"
#include "modules.h"
#include "messaging.h"
#include "ssl.h"
#include "global.h"
#include "serverlib.h"

#include "servers.pb-c.h"



/*
 * Write to the control stream.
 */
static int do_control_write(BIO *ctrl, void *data, uint32_t datalen) {
    fd_set writefds;
    struct timeval timeout;
    int fd;
    int ready;
    int bytes;
    uint32_t total_written = 0;

    assert(ctrl);
    assert(data);

    BIO_get_fd(ctrl, &fd);

    do {
        /* make sure the underlying file descriptor is ready for writing */
        do {
            FD_ZERO(&writefds);
            FD_SET(fd, &writefds);

            timeout.tv_sec = CONTROL_CONNECTION_TIMEOUT;
            timeout.tv_usec = 0;

            ready = select(fd + 1, NULL, &writefds, NULL, &timeout);
        } while ( ready < 0 && errno == EINTR );

        if ( ready == 0 ) {
            Log(LOG_DEBUG, "Timeout writing control packet, aborting");
            return -1;
        }

        if ( ready < 0 ) {
            Log(LOG_WARNING, "Failed to write control packet: %s",
                    strerror(errno));
            return -1;
        }

        if ( FD_ISSET(fd, &writefds) ) {
            bytes = BIO_write(ctrl, data+total_written, datalen-total_written);
            if ( bytes == 0 ) {
                Log(LOG_DEBUG, "Remote end closed control connection");
                return -1;
            }

            if ( bytes < 0 ) {
                if ( !BIO_should_retry(ctrl) ) {
                    Log(LOG_WARNING, "Error reading from BIO");
                    return -1;
                }
            } else {
                /* there was enough data, record how much we wrote */
                total_written += bytes;
            }
        }
    } while (total_written < datalen);

    return total_written;
}



/*
 * XXX set SSL_MODE_AUTO_RETRY when creating SSL socket? Will that mean
 * we never have to deal with reads while writing, or writes while reading?
 */
int write_control_packet(BIO *ctrl, void *data, uint32_t datalen) {
    uint32_t ctrllen = ntohl(datalen);

    /*
     * There is no delimiter for protocol buffers, so we need to send the
     * length of the message that will follow
     */
    if ( do_control_write(ctrl, &ctrllen, sizeof(ctrllen)) != sizeof(ctrllen) ){
        Log(LOG_WARNING, "Failed to write server control packet length");
        return -1;
    }

    /* Send the actual protocol buffer message onto the stream now */
    if ( do_control_write(ctrl, data, datalen) != datalen ) {
        Log(LOG_WARNING, "Failed to write server control packet data");
        return -1;
    }

    return datalen;
}



static int do_control_read(BIO *ctrl, void *data, int datalen) {
    fd_set readfds;
    struct timeval timeout;
    int fd;
    int ready;
    int bytes;
    int total_read = 0;

    assert(ctrl);
    assert(data);

    BIO_get_fd(ctrl, &fd);

    do {
        /* make sure the underlying file descriptor is ready for reading */
        do {
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);

            timeout.tv_sec = CONTROL_CONNECTION_TIMEOUT;
            timeout.tv_usec = 0;

            ready = select(fd + 1, &readfds, NULL, NULL, &timeout);
        } while ( ready < 0 && errno == EINTR );

        if ( ready == 0 ) {
            Log(LOG_DEBUG, "Timeout reading control packet, aborting");
            return -1;
        }

        if ( ready < 0 ) {
            Log(LOG_WARNING, "Failed to read control packet: %s",
                    strerror(errno));
            return -1;
        }

        if ( FD_ISSET(fd, &readfds) ) {
            bytes = BIO_read(ctrl, data + total_read, datalen - total_read);
            if ( bytes == 0 ) {
                Log(LOG_DEBUG, "Remote end closed control connection");
                return 0;
            }

            /*
             * if we get an error, it might just be there isn't enough data
             * to decrypt the SSL response, we might need to wait for more
             */
            if ( bytes < 0 ) {
                if ( !BIO_should_retry(ctrl) ) {
                    Log(LOG_WARNING, "Error reading from BIO");
                    return -1;
                }
            } else {
                /* there was enough data, record how much we read */
                total_read += bytes;
            }
        }
    } while (total_read < datalen);

    return total_read;
}



/*
 * XXX set SSL_MODE_AUTO_RETRY when creating SSL socket?
 */
int read_control_packet(BIO *ctrl, void **data) {
    uint32_t datalen = 0;
    int result;

    /* read the 32 bit length field for this message */
    result = do_control_read(ctrl, &datalen, sizeof(datalen));

    if ( result != sizeof(datalen) ) {
        /* TODO do we want to return 0 and deal with it further up the chain? */
        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to read server control packet length");
        }
        return -1;
    }

    /* allocate storage for the following message */
    datalen = ntohl(datalen);
    *data = calloc(1, datalen);

    /* read the message */
    result = do_control_read(ctrl, *data, datalen);

    if ( result != datalen ) {
        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to read server control packet data");
        }
        free(*data);
        return -1;
    }

    return datalen;
}



/*
 *
 */
int send_control_hello(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options) {

    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Hello hello = AMPLET2__SERVERS__HELLO__INIT;

    Log(LOG_DEBUG, "Sending HELLO");

    hello.has_options = 1;
    hello.options = *options;

    msg.hello = &hello;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__HELLO;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    /*
     * We will take charge and free the options as well, the test shouldn't
     * require it any longer and it makes the calling function look ugly.
     */
    free(options->data);
    free(options);

    return result;
}



/*
 *
 */
int send_control_ready(test_type_t test, BIO *ctrl,
        uint16_t port) {

    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Ready ready = AMPLET2__SERVERS__READY__INIT;

    Log(LOG_DEBUG, "Sending READY with port %d", port);

    ready.has_test_port = 1;
    ready.test_port = port;
    msg.ready = &ready;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__READY;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int send_control_receive(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options){

    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Receive receive = AMPLET2__SERVERS__RECEIVE__INIT;

    Log(LOG_DEBUG, "Sending RECEIVE");

    if ( options ) {
        receive.has_options = 1;
        receive.options = *options;
    }

    msg.receive = &receive;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int send_control_send(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options) {

    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Send send = AMPLET2__SERVERS__SEND__INIT;

    Log(LOG_DEBUG, "Sending SEND");

    //send.has_test_port = 1;
    //send.test_port = port;

    if ( options ) {
        send.has_options = 1;
        send.options = *options;
    }

    msg.send = &send;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__SEND;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    /*
     * We will take charge and free the options as well, the test shouldn't
     * require it any longer and it makes the calling function look ugly.
     */
    if ( options ) {
        free(options->data);
        free(options);
    }

    return result;
}



/*
 * TODO how do extensions and things work? Better way to stick a specific
 * test report packet into a message than as a byte array?
 */
int send_control_result(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *data) {

    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Result resmsg = AMPLET2__SERVERS__RESULT__INIT;

    Log(LOG_DEBUG, "Sending RESULT");

    resmsg.result = *data;
    resmsg.has_result = 1;
    msg.result = &resmsg;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__RESULT;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int send_control_renew(test_type_t test, BIO *ctrl) {
    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Renew renew = AMPLET2__SERVERS__RENEW__INIT;

    Log(LOG_DEBUG, "Sending RENEW message");

    msg.renew = &renew;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__RENEW;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int parse_control_hello(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {

    Amplet2__Servers__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__HELLO ) {
        Log(LOG_WARNING, "Not a HELLO packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "HELLO is for wrong test type, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->hello || (parse_func && !msg->hello->has_options) ) {
        Log(LOG_WARNING, "Malformed HELLO packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    /* call the test specific function to get the test options */
    if ( parse_func && options ) {
        *options = parse_func(&msg->hello->options);
    } else if ( options ) {
        *options = NULL;
    }

    amplet2__servers__control__free_unpacked(msg, NULL);
    return 0;
}



/*
 *
 */
int parse_control_ready(test_type_t test, void *data, uint32_t len,
        uint16_t *port) {

    Amplet2__Servers__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__READY ) {
        Log(LOG_WARNING, "Not a READY packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "HELLO is for wrong test type, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->ready || !msg->ready->has_test_port ) {
        Log(LOG_WARNING, "Malformed READY packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    *port = msg->ready->test_port;

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
int parse_control_receive(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {

    Amplet2__Servers__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE ) {
        Log(LOG_WARNING, "Not a RECEIVE packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "HELLO is for wrong test type, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->receive || (parse_func && !msg->receive->has_options) ) {
        Log(LOG_WARNING, "Malformed RECEIVE packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( parse_func && options ) {
        *options = parse_func(&msg->receive->options);
    } else if ( options ) {
        *options = NULL;
    }

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
int parse_control_send(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {

    Amplet2__Servers__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__SEND ) {
        Log(LOG_WARNING, "Not a SEND packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "HELLO is for wrong test type, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->send || (parse_func && !msg->send->has_options) ) {
        Log(LOG_WARNING, "Malformed SEND packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( parse_func && options ) {
        *options = parse_func(&msg->send->options);
    } else if ( options ) {
        *options = NULL;
    }

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
static int parse_control_result(test_type_t test, void *data, uint32_t len,
        ProtobufCBinaryData *results ) {
    Amplet2__Servers__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__RESULT ) {
        Log(LOG_WARNING, "Not a RESULT packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "HELLO is for wrong test type, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->result || !msg->result->has_result/*|| !msg->result->result*/ ) {
        Log(LOG_WARNING, "Malformed RESULT packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    results->len = msg->result->result.len;
    results->data = malloc(results->len);
    memcpy(results->data, msg->result->result.data, msg->result->result.len);

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
int read_control_hello(test_type_t test, BIO *ctrl,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {
    void *data;
    int len;

    /* read the packet from the stream */
    if ( (len = read_control_packet(ctrl, &data)) < 0 ) {
        Log(LOG_WARNING, "Failed to read HELLO packet");
        return -1;
    }

    /* validate it as a HELLO packet and then try to extract options */
    if ( parse_control_hello(test, data, len, options, parse_func) < 0 ) {
        Log(LOG_WARNING, "Failed to parse HELLO packet");
        free(data);
        return -1;
    }

    free(data);

    return 0;
}



/*
 *
 */
int read_control_ready(test_type_t test, BIO *ctrl,
        uint16_t *port) {

    void *data;
    int len;

    if ( (len = read_control_packet(ctrl, &data)) < 0 ) {
        Log(LOG_ERR, "Failed to read READY packet");
        return -1;
    }

    if ( parse_control_ready(test, data, len, port) < 0 ) {
        Log(LOG_WARNING, "Failed to parse READY packet");
        free(data);
        return -1;
    }

    free(data);

    return 0;
}



/*
 *
 */
int read_control_result(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *results) {

    void *data;
    int len;

    Log(LOG_DEBUG, "Waiting for RESULT packet");

    if ( (len = read_control_packet(ctrl, &data)) < 0 ) {
        Log(LOG_ERR, "Failed to read READY packet");
        return -1;
    }

    if ( parse_control_result(test, data, len, results) < 0 ) {
        Log(LOG_WARNING, "Failed to parse RESULT packet");
        free(data);
        return -1;
    }

    free(data);

    return 0;
}



/*
 * Return the local address that the socket is using.
  */
struct addrinfo *get_socket_address(int sock) {
    struct addrinfo *addr;

    assert(sock > 0);

    /* make our own struct addrinfo */
    addr = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    addr->ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_storage));
    addr->ai_addrlen = sizeof(struct sockaddr_storage);

    /* ask to fill in the ai_addr portion for our socket */
    getsockname(sock, addr->ai_addr, &addr->ai_addrlen);

    /* we already know most of the rest, so fill that in too */
    addr->ai_family = ((struct sockaddr*)addr->ai_addr)->sa_family;
    addr->ai_socktype = SOCK_STREAM;
    addr->ai_protocol = IPPROTO_TCP;
    addr->ai_canonname = NULL;
    addr->ai_next = NULL;

    return addr;
}



/*
 * Set a socket option using setsockopt() and then immediately call
 * getsockopt() to make sure that the value was set correctly.
 */
static int set_and_verify_sockopt(int sock, int value, int proto,
        int opt, const char *optname) {

    socklen_t size = sizeof(value);
    int verify;

    /* try setting the sockopt */
    if ( setsockopt(sock, proto, opt, &value, size) < 0 ) {
        Log(LOG_WARNING, "setsockopt failed to set the %s option to %d: %s",
                optname,  value, strerror(errno));
        return -1;
    }

    /* and then verify that it worked */
    if ( getsockopt(sock, proto, opt, &verify, &size) < 0 ) {
        Log(LOG_WARNING, "getsockopt failed to get the %s option: %s",
                optname, strerror(errno));
        return -1;
    }

    if ( proto == SOL_SOCKET && (opt == SO_RCVBUF || opt == SO_SNDBUF ||
                opt == SO_RCVBUFFORCE || opt == SO_SNDBUFFORCE) ) {
        /* buffer sizes will be set to twice what was asked for */
        if ( value != verify / 2 ) {
            Log(LOG_WARNING,
                    "getsockopt() reports incorrect value for %s after setting:"
                    "got %d, expected %d", optname, verify, value);
            return -1;
        }
    } else if ( value != verify ) {
        /* all other values should match what was requested */
        Log(LOG_WARNING,
                "getsockopt() reports incorrect value for %s after setting:"
                "got %d, expected %d", optname, verify, value);
        return -1;
    }

    /* Success */
    return 0;
}



/*
 * Set all the relevant socket options that the test is requesting be set
 * (e.g. set buffer sizes, set MSS, disable Nagle).
 */
static void do_socket_setup(struct sockopt_t *options, int sock) {

    if ( options == NULL ) {
        return;
    }

    /* set TCP_MAXSEG option */
    if ( options->sock_mss > 0 ) {
        Log(LOG_DEBUG, "Setting TCP_MAXSEG to %d", options->sock_mss);
#ifdef TCP_MAXSEG
        set_and_verify_sockopt(sock, options->sock_mss, IPPROTO_TCP,
                TCP_MAXSEG, "TCP_MAXSEG");
#else
        Log(LOG_WARNING, "TCP_MAXSEG undefined, can not set it");
#endif
    }

    /* set TCP_NODELAY option */
    if ( options->sock_disable_nagle ) {
        Log(LOG_DEBUG, "Setting TCP_NODELAY to %d",options->sock_disable_nagle);
#ifdef TCP_NODELAY
        set_and_verify_sockopt(sock, options->sock_disable_nagle, IPPROTO_TCP,
                TCP_NODELAY, "TCP_NODELAY");
#else
        Log(LOG_WARNING, "TCP_NODELAY undefined, can not set it");
#endif
    }

    /* set SO_RCVBUF option */
    if ( options->sock_rcvbuf > 0 ) {
        Log(LOG_DEBUG, "Setting SO_RCVBUF to %d", options->sock_rcvbuf);
#ifdef SO_RCVBUF
        if (  set_and_verify_sockopt(sock, options->sock_rcvbuf, SOL_SOCKET,
                SO_RCVBUF, "SO_RCVBUF") < 0 ) {
#ifdef SO_RCVBUFFORCE
            /*
             * Like SO_RCVBUF but if user has CAP_ADMIN privilage ignores
             * /proc/max size
             */
            set_and_verify_sockopt(sock, options->sock_rcvbuf, SOL_SOCKET,
                    SO_RCVBUFFORCE, "SO_RCVBUFFORCE");
#endif /* SO_RCVBUFFORCE */
        }
#else
        Log(LOG_WARNING, "SO_RCVBUF undefined, can not set it");
#endif /* SO_RCVBUF */
    }

    /* set SO_SNDBUF option */
    if ( options->sock_sndbuf > 0 ) {
        Log(LOG_DEBUG, "Setting SO_SNDBUF to %d", options->sock_sndbuf);
#ifdef SO_SNDBUF
        if ( set_and_verify_sockopt(sock, options->sock_sndbuf, SOL_SOCKET,
                SO_SNDBUF, "SO_SNDBUF") < 0 ) {
#ifdef SO_SNDBUFFORCE
            /*
             * Like SO_RCVBUF but if user has CAP_ADMIN privilage ignores
             * /proc/max size
             */
            set_and_verify_sockopt(sock, options->sock_sndbuf, SOL_SOCKET,
                    SO_SNDBUFFORCE, "SO_SNDBUFFORCE");
#endif /* SO_SNDBUFFORCE */
        }
#else
        Log(LOG_WARNING, "SO_SNDBUF undefined, can not set it");
#endif /* SO_SNDBUF */
    }

    /* set SO_REUSEADDR option */
    if (options->reuse_addr ) {
        Log(LOG_DEBUG, "Setting SO_REUSEADDR to %d", options->reuse_addr);
#ifdef SO_REUSEADDR
        set_and_verify_sockopt(sock, options->reuse_addr, SOL_SOCKET,
                SO_REUSEADDR, "SO_REUSEADDR");
#else
        Log(LOG_WARNING, "SO_REUSEADDR undefined, can not set it");
#endif
    }
}



/**
 * Start listening on the given port for incoming tests
 *
 * @param port
 *              The port to listen for incoming connections
 *
 * @return the bound socket or return -1 if this fails
 */
int start_listening(struct socket_t *sockets, int port,
        struct sockopt_t *sockopts) {

    assert(sockets);
    assert(sockopts);

    sockets->socket = -1;
    sockets->socket6 =  -1;

    Log(LOG_DEBUG, "Start server listening on port %d", port);

    /* open an ipv4 and an ipv6 socket so we can configure them individually */
    if ( sockopts->sourcev4 &&
            (sockets->socket=socket(AF_INET, sockopts->socktype,
                                    sockopts->protocol)) < 0 ) {
        Log(LOG_WARNING, "Failed to open socket for IPv4: %s", strerror(errno));
    }

    if ( sockopts->sourcev6 &&
            (sockets->socket6=socket(AF_INET6, sockopts->socktype,
                                     sockopts->protocol)) < 0 ) {
        Log(LOG_WARNING, "Failed to open socket for IPv6: %s", strerror(errno));
    }

    /* make sure that at least one of them was opened ok */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
        Log(LOG_WARNING, "No sockets opened");
        return -1;
    }

    /* set all the socket options that have been asked for */
    if ( sockets->socket >= 0 ) {
        do_socket_setup(sockopts, sockets->socket);
        ((struct sockaddr_in*)
         (sockopts->sourcev4->ai_addr))->sin_port = ntohs(port);
    }

    if ( sockets->socket6 >= 0 ) {
        int one = 1;
        do_socket_setup(sockopts, sockets->socket6);
        /*
         * If we dont set IPV6_V6ONLY this socket will try to do IPv4 as well
         * and it will fail.
         */
        setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_V6ONLY, &one,
                sizeof(one));
        ((struct sockaddr_in6*)
         (sockopts->sourcev6->ai_addr))->sin6_port = ntohs(port);
    }

    /* bind them to interfaces and addresses as required */
    if ( sockopts->device &&
            bind_sockets_to_device(sockets, sockopts->device) < 0 ) {
        Log(LOG_ERR, "Unable to bind sockets to device, aborting test");
        return -1;
    }

    if ( bind_sockets_to_address(sockets, sockopts->sourcev4,
                sockopts->sourcev6) < 0 ) {
        /* XXX can we trust errno to always be set correctly at this point? */
        int error = errno;

        /* close any sockets that might have been open and bound ok */
        if ( sockets->socket >= 0 ) {
            close(sockets->socket);
        }
        if ( sockets->socket6 >= 0 ) {
            close(sockets->socket6);
        }

        /* if we got an EADDRINUSE we report it so a new port can be tried */
        if ( error == EADDRINUSE ) {
            return EADDRINUSE;
        }

        Log(LOG_ERR,"Unable to bind socket to address, aborting test");
        return -1;
    }

    /* Start listening for at most 1 connection, we don't want a huge queue */
    if ( sockets->socket >= 0 && sockopts->socktype == SOCK_STREAM ) {
        if ( listen(sockets->socket, 1) < 0 ) {
            int error = errno;
            Log(LOG_DEBUG, "Failed to listen on IPv4 socket: %s",
                    strerror(errno));

            /* close the failed ipv4 socket */
            close(sockets->socket);
            sockets->socket = -1;

            /* we'll try again if the address was already in use */
            if ( error == EADDRINUSE ) {
                /* close the ipv6 socket as well if it was opened */
                if ( sockets->socket6 >= 0 ) {
                    close(sockets->socket6);
                    sockets->socket6 = -1;
                }
                return EADDRINUSE;
            }
        }
    }

    if ( sockets->socket6 >= 0 && sockopts->socktype == SOCK_STREAM ) {
        if ( listen(sockets->socket6, 1) < 0 ) {
            int error = errno;
            Log(LOG_DEBUG, "Failed to listen on IPv6 socket: %s",
                    strerror(errno));

            /* close the failed ipv6 socket */
            close(sockets->socket6);
            sockets->socket6 = -1;

            /* we'll try again if the address was already in use */
            if ( error == EADDRINUSE ) {
                /* close the ipv4 socket as well if it was opened */
                if ( sockets->socket >= 0 ) {
                    close(sockets->socket);
                    sockets->socket = -1;
                }
                return EADDRINUSE;
            }
        }
    }

    /*
     * If the ports are free, make sure at least one was opened ok. For now,
     * we'll assume that if both were meant to open but one didn't then it
     * isn't anything we can fix by trying again.
     */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
        Log(LOG_WARNING, "No sockets listening");
        return -1;
    }

    Log(LOG_DEBUG, "Successfully listening on port %d", port);
    return 0;
}



/*
 * XXX should port be included in options?
 */
int connect_to_server(struct addrinfo *server, struct sockopt_t *options,
        int port) {

    int sock;

    sock = socket(server->ai_family, options->socktype, options->protocol);

    if ( sock < 0 ) {
        Log(LOG_WARNING, "Failed to create control socket:%s", strerror(errno));
        return -1;
    }

    do_socket_setup(options, sock);

    /*
     * Set options that are at the AMP test level rather than specific
     * to this test. We need to know what address family we
     * are connecting to, which doSocketSetup doesn't know.XXX
     */
    if ( options->device ) {
        if ( bind_socket_to_device(sock, options->device) < 0 ) {
            return -1;
        }
    }

    if ( options->sourcev4 || options->sourcev6 ) {
        struct addrinfo *addr;

        switch ( server->ai_family ) {
            case AF_INET: addr = options->sourcev4; break;
            case AF_INET6: addr = options->sourcev6; break;
            default: printf("get address to bind with\n"); return -1;
        };

        /*
         * Only bind if we have a specific source with the same address
         * family as the destination, otherwise leave it default.
         */
        if ( addr && bind_socket_to_address(sock, addr) < 0 ) {
            return -1;
        }
    }

    /*
     * It should be safe to use the IPv4 structure here since the port is in
     * the same place in both headers.
     */
     //XXX why not make this the only code path? are we setting port in the
     // structure earlier? throughput test did this, but not sure why
     //if ( ((struct sockaddr_in *)serv_addr->ai_addr)->sin_port == 0 ) {
    if ( port > 0 ) {
        ((struct sockaddr_in *)server->ai_addr)->sin_port = htons(port);
    }

    Log(LOG_DEBUG, "Connecting using port %d", (int)ntohs(
                ((struct sockaddr_in *)server->ai_addr)->sin_port));

    if ( connect(sock, server->ai_addr, server->ai_addrlen) < 0 ) {
        Log(LOG_WARNING, "Failed to connect to server: %s", strerror(errno));
        close(sock);
        return -1;
    }

    //XXX why is this done? the throughput test did it, but not sure why
    ((struct sockaddr_in *)server->ai_addr)->sin_port = 0;

    return sock;
}
