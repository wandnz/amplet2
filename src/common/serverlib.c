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
 *
 */
static int write_control_packet(int sock, void *data, uint32_t len) {
    int result;
    uint32_t total_written = 0;
    uint32_t datalen = ntohl(len);

    printf("sending %d bytes\n", sizeof(datalen));
    do {
        result = write(sock, (uint8_t *)&datalen + total_written,
                sizeof(datalen) - total_written);

        if ( result < 0 && errno == EINTR ) {
            continue;
        }

        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to write server control packet length: %s",
                    strerror(errno));
            return -1;
        }

        total_written += result;

    } while ( total_written < sizeof(datalen));

    assert(total_written == sizeof(datalen));

    total_written = 0;

    printf("sending %d bytes\n", len);
    do {
        result = write(sock, (uint8_t *)data+total_written, len-total_written);

        if ( result < 0 && errno == EINTR ) {
            continue;
        }

        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to write server control packet length");
            return -1;
        }

        total_written += result;

    } while ( total_written < len );

    assert(total_written == len);

    return total_written;
}



/*
 *
 */
int read_control_packet(int sock, void **data) {
    int result;
    uint32_t datalen = 0;
    uint32_t bytes_read = 0;

    /* read the length of the following protocol buffer object */
    do {
        result = read(sock, ((uint8_t *)&datalen) + bytes_read,
                sizeof(datalen) - bytes_read);

        if ( result < 0 && errno == EINTR ) {
            continue;
        }

        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to read server control packet length");
            return -1;
        }

        if ( result == 0 ) {
            Log(LOG_DEBUG, "Server control connection closed");
            return -1;
        }

        bytes_read += result;

    } while ( bytes_read < sizeof(datalen) );

    assert(bytes_read == sizeof(datalen));

    printf("read %d bytes, expect %d more to follow\n", bytes_read,
            ntohl(datalen));

    bytes_read = 0;
    datalen = ntohl(datalen);
    *data = calloc(1, datalen);

    /* read the protocol buffer object from the stream */
    do {
        result = read(sock, ((uint8_t *)*data)+bytes_read, datalen-bytes_read);

        if ( result < 0 && errno == EINTR ) {
            continue;
        }

        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to read server control packet data");
            return -1;
        }

        if ( result == 0 ) {
            Log(LOG_DEBUG, "Server control connection closed");
            return -1;
        }

        bytes_read += result;

    } while ( bytes_read < datalen );

    assert(datalen == bytes_read);

    printf("read object of %d bytes\n", datalen);

    return datalen;
}



/*
 *
 */
int send_control_hello(int sock, struct temp_sockopt_t_xxx *options) {
    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Hello hello = AMPLET2__SERVERS__HELLO__INIT;

    printf("sending hello\n");

    hello.has_test_port = 1;
    hello.test_port = options->tport;
    hello.has_packet_size = 1;
    hello.packet_size = options->packet_size;
    hello.has_packet_count = 1;
    hello.packet_count = options->packet_count;
    hello.has_packet_spacing = 1;
    hello.packet_spacing = options->packet_spacing;
    hello.has_percentile_count = 1;
    hello.percentile_count = options->percentile_count;

    printf(" - test port %d\n", options->tport);
    printf(" - packet size %d\n", options->packet_size);
    printf(" - packet count %d\n", options->packet_count);
    printf(" - packet spacing %d\n", options->packet_spacing);
    printf(" - percentiles %d\n", options->percentile_count);

    msg.hello = &hello;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__HELLO;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(sock, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int send_control_ready(int sock, uint16_t port) {
    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Ready ready = AMPLET2__SERVERS__READY__INIT;

    printf("sending ready with port %d\n", port);

    ready.has_test_port = 1;
    ready.test_port = port;
    msg.ready = &ready;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__READY;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(sock, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int send_control_receive(int sock, uint32_t packet_count) {
    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Receive receive = AMPLET2__SERVERS__RECEIVE__INIT;

    printf("sending receive\n");

    receive.has_packet_count = 1;
    receive.packet_count = packet_count;
    msg.receive = &receive;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(sock, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int send_control_send(int sock, uint16_t port) {
    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Send send = AMPLET2__SERVERS__SEND__INIT;

    printf("sending send\n");

    send.has_test_port = 1;
    send.test_port = port;
    msg.send = &send;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__SEND;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(sock, buffer, len);

    free(buffer);

    return result;
}



/*
 * TODO how do extensions and things work? Better way to stick a specific
 * test report packet into a message than as a byte array?
 */
int send_control_result(int sock, ProtobufCBinaryData *data) {
    int len;
    void *buffer;
    int result;
    Amplet2__Servers__Control msg = AMPLET2__SERVERS__CONTROL__INIT;
    Amplet2__Servers__Result resmsg = AMPLET2__SERVERS__RESULT__INIT;

    printf("sending results, data length %d\n", data->len);

    resmsg.result = *data;
    resmsg.has_result = 1;
    msg.result = &resmsg;
    msg.has_type = 1;
    msg.type = AMPLET2__SERVERS__CONTROL__TYPE__RESULT;

    len = amplet2__servers__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__servers__control__pack(&msg, buffer);

    result = write_control_packet(sock, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
int parse_control_hello(void *data, uint32_t len,
        struct temp_sockopt_t_xxx *options) {

    Amplet2__Servers__Control *msg;

    assert(data);
    assert(options);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__HELLO ) {
        Log(LOG_WARNING, "Not a HELLO packet, aborting");
        printf("type:%d\n", msg->type);
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->hello || !msg->hello->has_test_port ) {
        Log(LOG_WARNING, "Malformed HELLO packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    options->tport = msg->hello->test_port;
    options->packet_size = msg->hello->packet_size;
    options->packet_count = msg->hello->packet_count;
    options->packet_spacing = msg->hello->packet_spacing;
    options->percentile_count = msg->hello->percentile_count;

    printf("read HELLO packet\n");
    printf(" - test port %d\n", options->tport);
    printf(" - packet size %d\n", options->packet_size);
    printf(" - packet count %d\n", options->packet_count);
    printf(" - packet spacing %d\n", options->packet_spacing);
    printf(" - percentiles %d\n", options->percentile_count);

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
int parse_control_ready(void *data, uint32_t len,
        struct temp_sockopt_t_xxx *options) {

    Amplet2__Servers__Control *msg;

    assert(data);
    assert(options);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__READY ) {
        Log(LOG_WARNING, "Not a READY packet, aborting");
        printf("type:%d\n", msg->type);
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->ready || !msg->ready->has_test_port ) {
        Log(LOG_WARNING, "Malformed READY packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    options->tport = msg->ready->test_port;
    printf("got control ready with test port %d\n", options->tport);

    /* TODO other test options */

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}


//XXX parse function takes inconsistent args
//XXX unpacked vs packed
int parse_control_receive(void *data, uint32_t len,
        struct temp_sockopt_t_xxx *options) {

    Amplet2__Servers__Control *msg;

    assert(data);
    assert(options);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE ) {
        Log(LOG_WARNING, "Not a RECEIVE packet, aborting");
        printf("type:%d\n", msg->type);
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->receive || !msg->receive->has_packet_count ) {
        Log(LOG_WARNING, "Malformed RECEIVE packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    options->packet_count = msg->receive->packet_count;
    printf("got control receive with packet count %d\n", options->packet_count);

    /* TODO other test options */

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
static int parse_control_result(void *data, uint32_t len,
        ProtobufCBinaryData *results ) {
    Amplet2__Servers__Control *msg;

    assert(data);
    //assert(options);

    /* unpack all the data */
    msg = amplet2__servers__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__SERVERS__CONTROL__TYPE__RESULT ) {
        Log(LOG_WARNING, "Not a RESULT packet, aborting");
        printf("type:%d\n", msg->type);
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->result || !msg->result->has_result/*|| !msg->result->result*/ ) {
        Log(LOG_WARNING, "Malformed RESULT packet, aborting");
        amplet2__servers__control__free_unpacked(msg, NULL);
        return -1;
    }

    printf("got result packet, data has length %d\n", msg->result->result.len);

    results->len = msg->result->result.len;
    results->data = malloc(results->len);
    memcpy(results->data, msg->result->result.data, msg->result->result.len);

    amplet2__servers__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
int read_control_hello(int sock, struct temp_sockopt_t_xxx *options) {
    void *data;
    int len;

    if ( (len=read_control_packet(sock, &data)) < 0 ) {
        Log(LOG_WARNING, "Failed to read HELLO packet");
        return -1;
    }

    if ( parse_control_hello(data, len, options) < 0 ) {
        Log(LOG_WARNING, "Failed to parse HELLO packet");
        return -1;
    }

    return 0;
}



/*
 *
 */
int read_control_ready(int sock, struct temp_sockopt_t_xxx *options) {
    void *data;
    int len;

    if ( (len=read_control_packet(sock, &data)) < 0 ) {
        Log(LOG_ERR, "Failed to read READY packet");
        return -1;
    }

    if ( parse_control_ready(data, len, options) < 0 ) {
        Log(LOG_WARNING, "Failed to parse READY packet");
        return -1;
    }

    return 0;
}



/*
 *
 */
int read_control_result(int sock, ProtobufCBinaryData *results) {
    void *data;
    int len;

    printf("waiting for result packet\n");

    if ( (len=read_control_packet(sock, &data)) < 0 ) {
        Log(LOG_ERR, "Failed to read READY packet");
        return -1;
    }

    if ( parse_control_result(data, len, results) < 0 ) {
        Log(LOG_WARNING, "Failed to parse RESULT packet");
        return -1;
    }

    return 0;
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
        struct temp_sockopt_t_xxx *sockopts) {

    assert(sockets);
    assert(sockopts);

    sockets->socket = -1;
    sockets->socket6 =  -1;

    printf("start listening\n");

    /* open an ipv4 and an ipv6 socket so we can configure them individually */
    if ( sockopts->sourcev4 &&
            (sockets->socket=socket(AF_INET, sockopts->socktype, sockopts->protocol)) < 0 ) {
        Log(LOG_WARNING, "Failed to open socket for IPv4: %s", strerror(errno));
    }

    if ( sockopts->sourcev6 &&
            (sockets->socket6=socket(AF_INET6, sockopts->socktype, sockopts->protocol)) < 0 ){
        Log(LOG_WARNING, "Failed to open socket for IPv6: %s", strerror(errno));
    }

    /* make sure that at least one of them was opened ok */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
        Log(LOG_WARNING, "No sockets opened");
        return -1;
    }

    /* set all the socket options that have been asked for */
    if ( sockets->socket >= 0 ) {
        //doSocketSetup(sockopts, sockets->socket); XXX
        ((struct sockaddr_in*)
         (sockopts->sourcev4->ai_addr))->sin_port = ntohs(port);
    }

    if ( sockets->socket6 >= 0 ) {
        int one = 1;
        //doSocketSetup(sockopts, sockets->socket6); XXX
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
int connect_to_server(struct addrinfo *server,
        struct temp_sockopt_t_xxx *options, int port) {

    int sock;

    //XXX why SOCK_STREAM? needs to able to do DGRAM too, and change protocols
    sock = socket(server->ai_family, options->socktype, options->protocol);

    if ( sock < 0 ) {
        Log(LOG_WARNING, "Failed to create control socket:%s", strerror(errno));
        return -1;
    }

    //XXX do socket setup

    /*
     * Set options that are at the AMP test level rather than specific
     * to this test. We need to know what address family we
     * are connecting to, which doSocketSetup doesn't know.XXX
     */
    if ( options->device ) {
        if ( bind_socket_to_device(sock, options->device) < 0 ) {
            printf("bind to device\n");
            return -1;
        }
    }

#if 0
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
            printf("bind to address\n");
            return -1;
        }
    }
#endif
    /*
     * It should be safe to use the IPv4 structure here since the port is in
     * the same place in both headers.
     */
     //XXX why not make this the only code path? are we setting port in the
     // structure earlier?
    //if ( port > 0 ) {
        printf("setting port to %d\n", port);
        ((struct sockaddr_in *)server->ai_addr)->sin_port = htons(port);
    //}

    if ( connect(sock, server->ai_addr, server->ai_addrlen) < 0 ) {
        Log(LOG_WARNING, "Failed to connect to server: %s", strerror(errno));
        close(sock);
        return -1;
    }

    //XXX why is this done?
    ((struct sockaddr_in *)server->ai_addr)->sin_port = 0;

    return sock;
}
