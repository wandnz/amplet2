#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include "ssl.h"
#include "tests.h"
#include "serverlib.h"
#include "testlib.h"
#include "udpstream.h"
#include "controlmsg.h"
#include "controlmsg.pb-c.h"
#include "debug.h"



/*
 * Notify the remote end that we are ready to receive test data, receive the
 * stream of test data, then send back results from our side of the connection.
 * TODO return failure from here if things go poorly
 */
static void do_receive(BIO *ctrl, int test_sock, struct opt_t *options) {

    Amplet2__Udpstream__Item *result;
    ProtobufCBinaryData packed;
    struct timeval *times = NULL;

    Log(LOG_DEBUG, "got RECEIVE command");

    /* we are going to track a timeval for every expected packet */
    times = calloc(options->packet_count, sizeof(struct timeval));

    /* tell the client what port the test server is running on */
    send_control_ready(AMP_TEST_UDPSTREAM, ctrl, options->tport);

    /* wait for the data stream from the client */
    receive_udp_stream(test_sock, options, times);

    /* build a protobuf message containing our side of the results */
    result = report_stream(UDPSTREAM_TO_SERVER, NULL, times, options);

    /* pack the result for sending to the client */
    packed.len = amplet2__udpstream__item__get_packed_size(result);
    packed.data = malloc(packed.len);
    amplet2__udpstream__item__pack(result, packed.data);

    /* send the result to the client for reporting */
    send_control_result(AMP_TEST_UDPSTREAM, ctrl, &packed);

    amplet2__udpstream__item__free_unpacked(result, NULL);
    free(packed.data);
    free(times);
}



/*
 * Send a stream of test data, then send back results from our side of the
 * test connection.
 * TODO return failure from here if things go poorly
 */
static void do_send(BIO *ctrl, int test_sock, struct sockaddr_storage *remote,
        uint16_t port, struct opt_t *options) {

    Amplet2__Udpstream__Item *item;
    ProtobufCBinaryData packed;
    struct addrinfo client;
    struct summary_t *rtt;

    Log(LOG_DEBUG, "got SEND command with port %d", port);

    /*
     * the target is the same host we are connected to on the control socket,
     * but over UDP and using the port we are told to use
     */
    client.ai_flags = 0;
    client.ai_family = remote->ss_family;
    client.ai_socktype = SOCK_DGRAM;
    client.ai_protocol = IPPROTO_UDP;
    client.ai_addr = (struct sockaddr*)remote;
    ((struct sockaddr_in*)client.ai_addr)->sin_port = ntohs(port);

    if ( client.ai_family == AF_INET ) {
        client.ai_addrlen = sizeof(struct sockaddr_in);
    } else {
        client.ai_addrlen = sizeof(struct sockaddr_in6);
    }

    client.ai_canonname = NULL;
    client.ai_next = NULL;

    /* perform the actual test to the client destination we just created */
    rtt = send_udp_stream(test_sock, &client, options);

    /* build a protobuf message containing the measured rtt */
    item = (Amplet2__Udpstream__Item*)malloc(sizeof(Amplet2__Udpstream__Item));
    amplet2__udpstream__item__init(item);
    item->rtt = report_summary(rtt);

    /* pack the result for sending to the client */
    packed.len = amplet2__udpstream__item__get_packed_size(item);
    packed.data = malloc(packed.len);
    amplet2__udpstream__item__pack(item, packed.data);

    /* send the result to the client for reporting */
    send_control_result(AMP_TEST_UDPSTREAM, ctrl, &packed);

    free(rtt);
    free(item->rtt);
    free(item);
    free(packed.data);
}



/*
 * Perform the test.
 */
static int serve_test(BIO *ctrl, struct sockopt_t *sockopts) {
    struct sockaddr_storage remote;
    socklen_t remote_addrlen;
    struct socket_t sockets;
    uint16_t portmax;
    int test_sock;
    int res;
    int bytes;
    struct opt_t *options;
    void *data;

    options = NULL;
    remote_addrlen = sizeof(remote);

    /* get the address of the remote machine, so we know who to send to */
    if ( getpeername(BIO_get_fd(ctrl, NULL), (struct sockaddr*)&remote,
                &remote_addrlen) < 0 ) {
        Log(LOG_WARNING, "Failed to get remote peer: %s", strerror(errno));
        return -1;
    }

    /* the HELLO packet describes all the global test options */
    if ( read_control_hello(AMP_TEST_UDPSTREAM, ctrl, (void**)&options,
                parse_hello) < 0 ) {
        Log(LOG_WARNING, "Got bad HELLO packet, shutting down test server");
        return -1;
    }

    /*
     * Try to create the test server on the appropriate port. If test port has
     * been manually set, only try that port. If it is still the default, try
     * a few ports till we hopefully find a free one.
     */
    if ( options->tport == DEFAULT_TEST_PORT ) {
        portmax = MAX_TEST_PORT;
    } else {
        if ( options->tport < IPPORT_RESERVED ) {
            Log(LOG_WARNING, "Not allowing test ports < 1024");
            return -1;
        }
        portmax = options->tport;
    }

    /* configure the new UDP test socket */
    sockopts->socktype = SOCK_DGRAM;
    sockopts->protocol = IPPROTO_UDP;

    /* No errors so far, make our new test socket with the given test options */
    do {
        res = start_listening(&sockets, options->tport, sockopts);
    } while ( res == EADDRINUSE && options->tport++ < portmax );

    if ( res != 0 ) {
        Log(LOG_WARNING, "Failed to start listening for test traffic");
        return -1;
    }

    assert(sockets.socket > 0 || sockets.socket6 > 0);

    /*
     * Only a single socket should be listening now, and it should be on the
     * same address that the original control connection arrived on.
     */
    if ( sockets.socket > 0 ) {
        Log(LOG_DEBUG, "Serving test over IPv4");
        test_sock = sockets.socket;
    } else {
        Log(LOG_DEBUG, "Serving test over IPv6");
        test_sock = sockets.socket6;
    }

    while ( (bytes = read_control_packet(ctrl, &data)) > 0 ) {
        Amplet2__Controlmsg__Control *msg;
        msg = amplet2__controlmsg__control__unpack(NULL, bytes, data);

        switch ( msg->type ) {
            case AMPLET2__CONTROLMSG__CONTROL__TYPE__SEND: {
                struct opt_t *send_opts;
                /* validate as a proper SEND message and extract port */
                if ( parse_control_send(AMP_TEST_UDPSTREAM, data, bytes,
                            (void**)&send_opts, parse_send) < 0 ) {
                    return -1;
                }

                do_send(ctrl, test_sock, &remote, send_opts->tport, options);
                free(send_opts);
                break;
            }

            case AMPLET2__CONTROLMSG__CONTROL__TYPE__RECEIVE: {
                /* validate it as a proper RECEIVE message */
                if ( parse_control_receive(AMP_TEST_UDPSTREAM, data, bytes,
                            NULL, NULL) < 0 ) {
                    return -1;
                }

                do_receive(ctrl, test_sock, options);
                break;
            }

            /* TODO send a close/finished message? */

            default: Log(LOG_WARNING, "Unhandled message type %d", msg->type);
                     break;
        };

        /* both read_control_packet and unpacking the buffer allocate memory */
        free(data);
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
    }

    close(test_sock);
    free(options);

    return 0;
}



/*
 * The main function of the udpstream server.
 */
void run_udpstream_server(int argc, char *argv[], BIO *ctrl) {
    int port; /* Port to start server on */
    int opt;
    struct sockopt_t sockopts;
    char *sourcev4, *sourcev6;
    extern struct option long_options[];
    uint16_t portmax;
    int standalone;

    /* Possibly could use dests to limit interfaces to listen on */

    Log(LOG_DEBUG, "Running udpstream test as server");

    /* set some sensible defaults */
    memset(&sockopts, 0, sizeof(sockopts));
    sourcev4 = "0.0.0.0";
    sourcev6 = "::";
    port = DEFAULT_CONTROL_PORT;
    portmax = MAX_CONTROL_PORT;
    standalone = 0;

    while ( (opt = getopt_long(argc, argv, "p:I:Q:Z:4:6:hx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4': sourcev4 = optarg; break;
            case '6': sourcev6 = optarg; break;
            case 'I': sockopts.device = optarg; break;
            case 'Q': /* option does nothing for this test */ break;
            case 'Z': /* option does nothing for this test */ break;
            case 'p': port = atoi(optarg); portmax = port; break;
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h':
            default: usage(); return;
        };
    }

    Log(LOG_DEBUG, "udpstream server port=%d, maxport=%d", port, portmax);

    /* TODO use the port number here rather than in start_listening() */
    sockopts.sourcev4 = get_numeric_address(sourcev4, NULL);
    sockopts.sourcev6 = get_numeric_address(sourcev6, NULL);
    sockopts.socktype = SOCK_STREAM;
    sockopts.protocol = IPPROTO_TCP;
    sockopts.reuse_addr = 1;

    if ( !ctrl ) {
        /* The server was started standalone, wait for a control connection */
        standalone = 1;
        Log(LOG_DEBUG, "udpstream server trying to listen on port %d", port);
        if ( (ctrl=listen_control_server(port, portmax, &sockopts)) == NULL ) {
            Log(LOG_WARNING, "Failed to establish control connection");
            return;
        }
    }

    /* this will serve the test only on the address we got connected to on */
    serve_test(ctrl, &sockopts);

    /* we made the control connection ourselves */
    if ( standalone ) {
        /* addrinfo structs were manually allocated, so free them manually */
        if ( sockopts.sourcev4 ) {
            free(sockopts.sourcev4->ai_addr);
            free(sockopts.sourcev4);
        }

        if ( sockopts.sourcev6 ) {
            free(sockopts.sourcev6->ai_addr);
            free(sockopts.sourcev6);
        }

        close_control_connection(ctrl);
    }

    return;
}
