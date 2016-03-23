/**
 * The AMP throughput client, see the usage for details.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */

#include <getopt.h>
#include <assert.h>

#include "ssl.h"
#include "serverlib.h"
#include "throughput.h"
#include "controlmsg.h"
#include "controlmsg.pb-c.h"
#include "debug.h"



/**
 * Return the port a socket is listening on
 *
 * @param sock_fd
 *          The socket to retrive the port from.
 * @return Host order port
 */
static uint16_t getSocketPort(int sock_fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);

    assert(sock_fd > 0);

    getsockname(sock_fd, (struct sockaddr*)&ss,  &len);
    if ( ((struct sockaddr *)&ss)->sa_family == AF_INET ) {
        return ntohs((((struct sockaddr_in*)&ss)->sin_port));
    } else {
        return ntohs((((struct sockaddr_in6*)&ss)->sin6_port));
    }
}



/*
 *
 */
static int do_receive(BIO *ctrl, int test_sock) {
    Amplet2__Throughput__Item *item;
    ProtobufCBinaryData packed;
    struct test_result_t result;
    struct test_request_t request;

    memset(&result, 0, sizeof(result));
    memset(&request, 0, sizeof(request));

    /* Send READY here so timestamp is accurate */
    send_control_ready(AMP_TEST_THROUGHPUT, ctrl, 0);

    if ( incomingTest(test_sock, &result) != 0 ) {
        return -1;
    }

#if 0
    if ( !sockopts->disable_web10g ) {
        web10g = getWeb10GSnap(test_sock);
    }
#endif

    /* Send our result */
    request.type = TPUT_2_SERVER;
    request.s_result = &result;

    item = report_schedule(&request);

    /* pack the result for sending to the client */
    packed.len = amplet2__throughput__item__get_packed_size(item);
    packed.data = malloc(packed.len);
    amplet2__throughput__item__pack(item, packed.data);

    if ( send_control_result(AMP_TEST_THROUGHPUT, ctrl, &packed) < 0 ) {
        free(item);
        free(packed.data);
        return -1;
    }

#if 0
    if ( web10g != NULL ) {
        free(web10g);
    }
#endif

    free(item);
    free(packed.data);

    return 0;
}


static int do_send(BIO *ctrl, int test_sock, struct opt_t *options,
        struct test_request_t *request) {

    Amplet2__Throughput__Item *item;
    ProtobufCBinaryData packed;
    struct test_result_t result;
#if 0
    struct report_web10g_t *web10g = NULL;
#endif

    memset(&result, 0, sizeof(result));

    request->randomise = options->randomise;

    Log(LOG_DEBUG,"Got send request, dur:%d bytes:%d writes:%d",
            request->duration, request->bytes,
            request->write_size);

    /* Send the actual packets */
    switch ( sendPackets(test_sock, request, &result) ) {
        case -1:
            /* Failed to write to socket */
            return -1;
#if 0
        case 1:
            /* Bad test request, lets send a packet to keep the
             * client happy it's still expecting something.
             * XXX Why do it like this?
             */
            //XXX THIS WON"T WORK, ITS A NORMAL SOCKET
            if ( send_control_receive(test_sock, 0) < 0 ) {
                return -1;
            }
            /* Fall through on purpose! */
#endif
        case 0:
            /* Success or our fake success from case 1: */
#if 0
            if ( !options->disable_web10g ) {
                web10g = getWeb10GSnap(test_sock);
            }
#endif

            /* Unlike old test, send result for either direction */
            memset(request, 0, sizeof(*request));
            request->type = TPUT_2_CLIENT;
            request->c_result = &result;
            item = report_schedule(request);

            /* pack the result for sending to the client */
            packed.len = amplet2__throughput__item__get_packed_size(item);
            packed.data = malloc(packed.len);
            amplet2__throughput__item__pack(item, packed.data);

            /* send result to the client for reporting */
            if ( send_control_result(AMP_TEST_THROUGHPUT, ctrl, &packed) < 0 ) {
                free(item);
                free(packed.data);
                return -1;
            }

            free(item);
            free(packed.data);
            break;
    };

#if 0
    if ( web10g != NULL ) {
        free(web10g);
    }
#endif

    return 0;
}



static int do_renew(BIO *ctrl, int test_sock, uint16_t port, uint16_t portmax,
        struct sockopt_t *sockopts) {

    struct packet_t packet;
    struct socket_t sockets;
    int t_listen;
    int res;

    Log(LOG_DEBUG, "Client asked to renew the connection");

    memset(&packet, 0, sizeof(packet));

    /* Ready the listening socket again */
    do {
        res = start_listening(&sockets, port, sockopts);
    } while ( res == EADDRINUSE && port++ < portmax );

    if ( res != 0 ) {
        Log(LOG_ERR, "Failed to open listening socket terminating");
        return -1;
    }

    if ( sockets.socket > 0 ) {
        t_listen = sockets.socket;
    } else {
        t_listen = sockets.socket6;
    }

    /* Finish this side of the TCP connection */
    shutdown(test_sock, SHUT_WR);

    /* Now the client has also closed */
    if ( readPacket(test_sock, &packet, NULL) != 0 ) {
        Log(LOG_WARNING,
                "TPUT_NEW_CONNECTION expected the connection to be closed");
    }
    close(test_sock);

    send_control_ready(AMP_TEST_THROUGHPUT, ctrl, getSocketPort(t_listen));
    do {
        test_sock = accept(t_listen, NULL, NULL);
    } while (test_sock == -1 && errno == EINTR);

    if ( test_sock == -1 ) {
        Log(LOG_ERR, "Failed to accept after connection reset");
        return -1;
    }

    /* Close the listening socket again */
    close(t_listen);

    return 0;
}



/**
 * Serves a test for a connected client
 *
 * @param server_address Address of the server to connect to and run the test
 * @param options A copy of the program options which also contains the sequence
 *
 * @return 0 if successful, -1 upon error.
 */
static int serveTest(BIO *ctrl, struct sockopt_t *sockopts) {
    int bytes;
    int t_listen = -1;
    int test_sock = -1;
    struct socket_t sockets;
    uint16_t portmax;
    int res;
    void *data;
    struct opt_t *options = NULL;

    /* Read the hello and check we are compatible */
    Log(LOG_DEBUG, "Waiting for HELLO message");
    if ( read_control_hello(AMP_TEST_THROUGHPUT, ctrl, (void**)&options,
                parse_hello) < 0 ) {
        goto errorCleanup;
    }

    /* If test port has been manually set, only try that port. If it is
     * still the default, try a few ports till we hopefully find a free one.
     */
    if ( options->tport == DEFAULT_TEST_PORT ) {
        portmax = MAX_TEST_PORT;
    } else {
        portmax = options->tport;
    }

    /* No errors so far, make our new testsocket with the given test options */
    Log(LOG_DEBUG, "Starting test socket");
    do {
        res = start_listening(&sockets, options->tport, sockopts);
    } while ( res == EADDRINUSE && options->tport++ < portmax );

    if ( res != 0 ) {
        Log(LOG_WARNING, "Failed to start listening for test traffic");
        goto errorCleanup;
    }

    assert(sockets.socket > 0 || sockets.socket6 > 0);

    /*
     * Only a single socket should be listening now, and it should be on the
     * same address that the original control connection arrived on.
     */
    if ( sockets.socket > 0 ) {
        Log(LOG_DEBUG, "Serving test over IPv4");
        t_listen = sockets.socket;
    } else {
        Log(LOG_DEBUG, "Serving test over IPv6");
        t_listen = sockets.socket6;
    }

    /* send a packet over the control connection containing the test port */
    send_control_ready(AMP_TEST_THROUGHPUT, ctrl, getSocketPort(t_listen));
    Log(LOG_DEBUG, "Waiting for connection on test socket");

    //XXX this can block forever!
    do {
        test_sock = accept(t_listen, NULL, NULL);
    } while (test_sock == -1 && errno == EINTR ); /* Repeat if interrupted */

    /* For security best to close this here and re-open later if reconnecting */
    close(t_listen);
    t_listen = -1;

    if ( test_sock == -1 ) {
        Log(LOG_WARNING,
                "Failed to connect() upon our test listening socket: %s",
                strerror(errno));
    }

    /* Wait for something to do from the client */
    while ( (bytes = read_control_packet(ctrl, &data)) > 0 ) {
        Amplet2__Controlmsg__Control *msg;
        msg = amplet2__controlmsg__control__unpack(NULL, bytes, data);

        switch ( msg->type ) {
            case AMPLET2__CONTROLMSG__CONTROL__TYPE__RECEIVE: {
                if ( parse_control_receive(AMP_TEST_THROUGHPUT, data, bytes,
                            NULL, NULL) < 0 ) {
                    goto errorCleanup;
                }

                if ( do_receive(ctrl, test_sock) < 0 ) {
                    goto errorCleanup;
                }

                break;
            }

            case AMPLET2__CONTROLMSG__CONTROL__TYPE__SEND: {
                struct test_request_t *request;
                if ( parse_control_send(AMP_TEST_THROUGHPUT, data, bytes,
                            (void**)&request, parse_send) < 0 ) {
                    goto errorCleanup;
                }

                if ( do_send(ctrl, test_sock, options, request) < 0 ) {
                    goto errorCleanup;
                }

                free(request);

                break;
            }

            case AMPLET2__CONTROLMSG__CONTROL__TYPE__RENEW: {

                if ( do_renew(ctrl, test_sock, options->tport,
                            portmax, sockopts) < 0 ) {
                    goto errorCleanup;
                }

                break;
            }

            default: {
                /* Try and continue if we get a weird message */
                Log(LOG_WARNING, "Unhandled message type %d", msg->type);
                break;
            }
        };

        /* both read_control_packet and unpacking the buffer allocate memory */
        free(data);
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
    }

    free(options);

    if ( test_sock != -1 ) {
        close(test_sock);
    }
    return 0;

errorCleanup:
    /*
     * This should kick off the client - we assume they are waiting for us
     * somewhere
     */
    if ( test_sock != -1 ) {
        close(test_sock);
    }
    if ( t_listen != -1 ) {
        close(t_listen);
    }

    free(options);

    return -1;
}



/**
 * The main function of the throughput server.
 */
void run_throughput_server(int argc, char *argv[], BIO *ctrl) {
    int port; /* Port to start server on */
    int opt;
    struct sockopt_t sockopts;
    char *sourcev4, *sourcev6;
    extern struct option long_options[];
    uint16_t portmax;
    int standalone;

    /* Possibly could use dests to limit interfaces to listen on */

    Log(LOG_DEBUG, "Running throughput test as server");

    /* set some sensible defaults */
    memset(&sockopts, 0, sizeof(sockopts));
    sourcev4 = "0.0.0.0";
    sourcev6 = "::";
    port = DEFAULT_CONTROL_PORT;
    portmax = MAX_CONTROL_PORT;
    standalone = 0;

    /* TODO server should take long options too */
    while ( (opt = getopt_long(argc, argv, "?hp:4:6:I:Z:",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case 'Z': /* option does nothing for this test */ break;
            case '4': sourcev4 = optarg; break;
            case '6': sourcev6 = optarg; break;
            case 'I': sockopts.device = optarg; break;
            /* case 'B': for iperf compatability? */
            case 'p': port = atoi(optarg); portmax = port; break;
            case 'h':
            case '?':
            /* XXX do we need this extra usage statement here? */
            default: usage(argv[0]); return;
        };
    }

    Log(LOG_DEBUG, "Throughput server port=%d, maxport=%d", port, portmax);

    /* TODO use the port number here rather than in start_listening() */
    sockopts.sourcev4 = get_numeric_address(sourcev4, NULL);
    sockopts.sourcev6 = get_numeric_address(sourcev6, NULL);
    sockopts.socktype = SOCK_STREAM;
    sockopts.protocol = IPPROTO_TCP;
    sockopts.reuse_addr = 1;

    if ( !ctrl ) {
        /* The server was started standalone, wait for a control connection */
        standalone = 1;
        Log(LOG_DEBUG, "throughput server trying to listen on port %d", port);
        if ( (ctrl=listen_control_server(port, portmax, &sockopts)) == NULL ) {
            Log(LOG_WARNING, "Failed to establish control connection");
            return;
        }
    }

    /* this will serve the test only on the address we got connected to on */
    serveTest(ctrl, &sockopts);

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
