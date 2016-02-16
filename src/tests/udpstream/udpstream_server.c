#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include "tests.h"
#include "serverlib.h"
#include "testlib.h"
#include "udpstream.h"
#include "servers.pb-c.h"



/*
 * TODO return failure from here if things go poorly
 */
static void do_receive(int control_sock, int test_sock, struct opt_t *options) {

    Amplet2__Udpstream__Item *result;
    ProtobufCBinaryData packed;
    struct timeval *times = NULL;
    unsigned int i;

    printf("got RECEIVE command\n");

    /* we are going to track a timeval for every expected packet */
    times = calloc(options->packet_count, sizeof(struct timeval));

    /* tell the client what port the test server is running on */
    send_control_ready(control_sock, options->tport);

    /* wait for the data stream from the client */
    receive_udp_stream(test_sock, options->packet_count, times);

    /* build a protobuf message containing our side of the results */
    result = report_stream(UDPSTREAM_TO_SERVER, times, options);

    /* pack the result for sending to the client */
    packed.len = amplet2__udpstream__item__get_packed_size(result);
    packed.data = malloc(packed.len);
    amplet2__udpstream__item__pack(result, packed.data);

    /* send the result to the client for reporting */
    send_control_result(control_sock, &packed);

    for ( i = 0; i < result->n_loss_periods; i++ ) {
        free(result->loss_periods[i]);
    }
    free(result->loss_periods);
    free(result->percentiles);
    free(result);
    free(packed.data);
    free(times);
}



/*
 * TODO return failure from here if things go poorly
 */
static void do_send(int test_sock, struct sockaddr_storage *remote,
        uint16_t port, struct opt_t *options) {

    struct addrinfo client;

    printf("got SEND command with port %d\n", port);

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
    send_udp_stream(test_sock, &client, options);
}



//TODO make error messages make sense and not duplicated at all levels
// XXX can any of this move into a library function?
//XXX need remote when it can be extracted from control sock?
static int serve_test(int control_sock, struct sockaddr_storage *remote,
        struct temp_sockopt_t_xxx *sockopts) {
    struct socket_t sockets;
    uint16_t portmax;
    int test_sock;
    int res;
    int bytes;
    struct opt_t *options = NULL;
    void *data;

    /* the HELLO packet describes all the global test options */
    if ( read_control_hello(control_sock, &options, parse_hello) < 0 ) {
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

    /* XXX expect some magic passphrase exchanged via secure tcp connection? */


    while ( (bytes=read_control_packet(control_sock, &data)) > 0 ) {
        //XXX can this be made to only be udpstream messages?
        Amplet2__Servers__Control *msg;
        msg = amplet2__servers__control__unpack(NULL, bytes, data);

        switch ( msg->type ) {
            case AMPLET2__SERVERS__CONTROL__TYPE__SEND: {
                struct opt_t *send_opts;
                /* validate as a proper SEND message and extract port */
                if ( parse_control_send(data, bytes, &send_opts,
                            parse_send) < 0 ) {
                    return -1;
                }

                do_send(test_sock, remote, send_opts->tport, options);
                free(send_opts);
                break;
            }

            case AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE: {
                /* validate it as a proper RECEIVE message */
                if ( parse_control_receive(data, bytes, NULL, NULL) < 0 ) {
                    return -1;
                }

                do_receive(control_sock, test_sock, options);
                break;
            }

            /* TODO send a close/finished message? */

            default: Log(LOG_WARNING, "Unhandled message type %d\n", msg->type);
                     break;
        };

        /* both read_control_packet and unpacking the buffer allocate memory */
        free(data);
        amplet2__servers__control__free_unpacked(msg, NULL);
    }

    close(test_sock);
    free(options);

    return 0;
}



/*
 *
 */
void run_udpstream_server(int argc, char *argv[], SSL *ssl) {
    int port; /* Port to start server on */
    struct socket_t listen_sockets;
    int control_sock; /* Our clients control socket connection */
    int opt;
    //struct opt_t sockopts;
    struct temp_sockopt_t_xxx sockopts;//XXX this isn't the right thing to use
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    char *sourcev4, *sourcev6;
    int family;
    int maxwait;
    extern struct option long_options[];
    uint16_t portmax;
    int res;

    /* Possibly could use dests to limit interfaces to listen on */

    Log(LOG_DEBUG, "Running throughput test as server");

    /* set some sensible defaults */
    memset(&sockopts, 0, sizeof(sockopts));
    sourcev4 = "0.0.0.0";
    sourcev6 = "::";
    port = DEFAULT_CONTROL_PORT;
    portmax = MAX_CONTROL_PORT;

    while ( (opt = getopt_long(argc, argv, "?hp:4:6:I:Z:",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case 'Z': /* option does nothing for this test */ break;
            case '4': sourcev4 = optarg; break;
            case '6': sourcev6 = optarg; break;
            case 'I': sockopts.device = optarg; break;
            case 'p': port = atoi(optarg); portmax = port; break;
            case 'h':
            case '?':
            /* XXX do we need this extra usage statement here? */
            default: usage(argv[0]); return;
        };
    }

    Log(LOG_DEBUG, "udpstream server port=%d, maxport=%d", port, portmax);

    /* TODO use the port number here rather than in start_listening() */
    sockopts.sourcev4 = get_numeric_address(sourcev4, NULL);
    sockopts.sourcev6 = get_numeric_address(sourcev6, NULL);
    sockopts.socktype = SOCK_STREAM;
    sockopts.protocol = IPPROTO_TCP;
    sockopts.reuse_addr = 1;

    /* try to open a listen port for the control connection from a client */
    do {
        Log(LOG_DEBUG, "udpstream server trying to listen on port %d", port);
        //XXX pass a hints type struct?
        res = start_listening(&listen_sockets, port, &sockopts);
        printf("res=%d\n", res);
    } while ( res == EADDRINUSE && port++ < portmax );

    if ( res != 0 ) {
        Log(LOG_ERR, "Failed to open listening socket terminating");
        return;
    }

    /*
     * If SSL is not null, it means we have been started by the amplet client
     * and need to tell the other end what port it should connect to. If it
     * is NULL then we assume it is being run manually and the user knows
     * what port they want to use.
     */
    if ( ssl ) {
        if ( send_server_port(ssl, port) < 0 ) {
            Log(LOG_DEBUG, "Failed to send server port for throughput test\n");
            return;
        } else {
            Log(LOG_DEBUG, "Sent server port %d for throughput test OK", port);
        }
    }

    /* select on our listening sockets until someone connects */
    maxwait = MAXIMUM_SERVER_WAIT_TIME;
    if ( (family = wait_for_data(&listen_sockets, &maxwait)) <= 0 ) {
        Log(LOG_DEBUG, "Timeout out waiting for connection");
        return;
    }

    client_addrlen = sizeof(client_addr);
    switch ( family ) {
        case AF_INET: control_sock = accept(listen_sockets.socket,
                              (struct sockaddr*)&client_addr, &client_addrlen);
                      Log(LOG_DEBUG, "Got control connection on IPv4");
                      /* clear out the v6 address, it isn't needed any more */
                      freeaddrinfo(sockopts.sourcev6);
                      sockopts.sourcev6 = NULL;
                      /* set v4 address to where we received the connection */
                      freeaddrinfo(sockopts.sourcev4);
                      sockopts.sourcev4 = get_socket_address(control_sock);
                      break;

        case AF_INET6: control_sock = accept(listen_sockets.socket6,
                              (struct sockaddr*)&client_addr, &client_addrlen);
                      Log(LOG_DEBUG, "Got control connection on IPv6");
                      /* clear out the v4 address, it isn't needed any more */
                      freeaddrinfo(sockopts.sourcev4);
                      sockopts.sourcev4 = NULL;
                      /* set v6 address to where we received the connection */
                      freeaddrinfo(sockopts.sourcev6);
                      sockopts.sourcev6 = get_socket_address(control_sock);
                      break;

        default: return;
    };

    /* someone has connected, so close up all the listening sockets */
    if ( listen_sockets.socket > 0 ) {
        close(listen_sockets.socket);
    }

    if ( listen_sockets.socket6 > 0 ) {
        close(listen_sockets.socket6);
    }

    if ( control_sock < 0 ) {
        Log(LOG_WARNING, "Failed to accept connection: %s", strerror(errno));
        return;
    }

    Log(LOG_DEBUG, "Got a client connection");

    /* this will serve the test only on the address we got connected to on */
    serve_test(control_sock, &client_addr, &sockopts);
    close(control_sock);

    /* we made the addrinfo structs ourselves, so have to free them manually */
    if ( sockopts.sourcev4 ) {
        free(sockopts.sourcev4->ai_addr);
        free(sockopts.sourcev4);
    }

    if ( sockopts.sourcev6 ) {
        free(sockopts.sourcev6->ai_addr);
        free(sockopts.sourcev6);
    }

    return;
}
