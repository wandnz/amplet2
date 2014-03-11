/**
 * The AMP throughput client, see the usage for details.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */

#include <getopt.h>

#include "throughput.h"



/**
 * Start listening on the given port for incoming tests
 *
 * @param port
 *              The port to listen for incoming connections
 *
 * @return the bound socket or return -1 if this fails
 */
static int startListening(int port, struct opt_t *sockopts) {
    int sock = -1;
    struct addrinfo hints;
    struct addrinfo *addrs, *current;
    char portstr[10];

    /* Get all interfaces and in order attempt to bind to them */
    memset(&hints, 0, sizeof(hints));

    /* Allow IPv6 note AI_V4MAPPED allows IPv4 I think ?? */
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    /* For wildcard IP address */
    hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ALL;

    /* Have to make our port number a string for getaddrinfo() :( */
    snprintf(portstr, sizeof(portstr), "%d", port);

    /* The hint should give us a IPv6 and IPv4 binding if possible */
    if ( getaddrinfo(NULL, portstr, &hints, &addrs) < 0 ) {
        Log(LOG_ERR, "getaddrinfo failed: %s", strerror(errno));
    }

    for ( current = addrs; current != NULL ; current = current->ai_next ) {

        /* Open a socket that we can listen on */
        if ( (sock = socket(current->ai_family, current->ai_socktype,
                        current->ai_protocol)) < 0 ) {
            Log(LOG_WARNING, "startListening failed to create a socket(): %s",
                    strerror(errno));
            continue;
        }
        /* Set socket options */
        doSocketSetup(sockopts, sock);

        if ( bind(sock, current->ai_addr, current->ai_addrlen) == 0) {
            break; /* successfully bound*/
        }

        /* State of socket is unknown after a failed bind() */
        close(sock);
        sock = -1;
    }

    freeaddrinfo(addrs);

    if ( sock == -1 ) {
        Log(LOG_ERR, "startListening failed to bind the listening socket");
        goto errorCleanup;
    }

    /* Start listening for at most 1 connection, we don't want a huge queue */
    if (listen(sock, 1) == -1) {
        Log(LOG_ERR, "startListening failed to listen on our bound socket: %s",
                strerror(errno));
        goto errorCleanup;
    }

    Log(LOG_DEBUG, "Successfully listening on port %s", portstr);
    return sock;

    errorCleanup:
    if ( sock != -1 ) {
        close(sock);
    }
    return -1;
}



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

    getsockname(sock_fd, (struct sockaddr*)&ss,  &len);
    if ( ((struct sockaddr *)&ss)->sa_family == AF_INET ) {
        return ntohs((((struct sockaddr_in*)&ss)->sin_port));
    } else {
        return ntohs((((struct sockaddr_in6*)&ss)->sin6_port));
    }
}



/**
 * Serves a test for a connected client
 *
 * @param server_address Address of the server to connect to and run the test
 * @param options A copy of the program options which also contains the sequence
 *
 * @return 0 if successful, -1 upon error.
 */
static int serveTest(int control_socket) {
    struct packet_t packet;
    struct test_result_t result;
    int bytes_read;
    struct report_web10g_t *web10g = NULL;
    struct opt_t sockopts;
    int t_listen = -1;
    int test_socket = -1;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    uint32_t version = 0;

    memset(&packet, 0, sizeof(packet));
    memset(&result, 0, sizeof(result));
    memset(&sockopts, 0, sizeof(sockopts));

    /* Read the hello and check we are compatable */
    bytes_read = readPacket(control_socket, &packet, NULL);

    if ( readHelloPacket(&packet, &sockopts, &version) != 0 ) {
        goto errorCleanup;
    }
    if ( version != AMP_THROUGHPUT_TEST_VERSION ) {
        Log(LOG_ERR, "Incompatable Client connecting they are version %"PRIu32" but I'm version %d",
                version, AMP_THROUGHPUT_TEST_VERSION);
        goto errorCleanup;
    }

    /* No errors so far, make our new testsocket with the given test options */
    sockopts.reuse_addr = 1;
    t_listen = startListening(sockopts.tport, &sockopts);
    if ( t_listen == -1 ) {
        Log(LOG_ERR, "Failed to open listening socket terminating");
        goto errorCleanup;
    }
    sendReadyPacket(control_socket, getSocketPort(t_listen));

    do {
        test_socket = accept(t_listen,
                (struct sockaddr*) &client_addr, &client_addrlen);
    } while (test_socket == -1 && errno == EINTR ); /* Repeat if interrupted */

    /* For security best to close this here and re-open later if reconnecting */
    close(t_listen);
    t_listen = -1;

    if ( test_socket == -1 ) {
        Log(LOG_WARNING,
                "Failed to connect() upon our test listening socket: %s",
                strerror(errno));
    }

    /* Wait for something to do from the client */
    while ( (bytes_read = readPacket(control_socket, &packet, NULL)) != 0 ) {
        switch ( packet.header.type ) {
            case TPUT_PKT_DATA:
                /* Send READY here so timestamp is accurate */
                sendReadyPacket(control_socket, 0);
                if ( incomingTest(test_socket, &result) != 0 ) {
                    goto errorCleanup;
                }

                if ( !sockopts.disable_web10g ) {
                    web10g = getWeb10GSnap(test_socket);
                }

                /* Send our result */
                if ( sendResultPacket(control_socket, &result, web10g) < 0 ) {
                    goto errorCleanup;
                }

                if ( web10g != NULL ) {
                    free(web10g);
                }
                web10g = NULL;
                continue;
            case TPUT_PKT_SEND:
                {
                    struct test_request_t req;
                    memset(&req, 0, sizeof(req));
                    memset(&result, 0, sizeof(result));
                    req.duration = packet.types.send.duration_ms;
                    req.write_size = packet.types.send.write_size;
                    req.bytes = packet.types.send.bytes;
                    req.randomise = sockopts.randomise;
                    Log(LOG_INFO, "Got send request, dur:%d bytes:%d writes:%d",
                            req.duration, req.bytes, req.write_size);

                    /* Send the actual packets */
                    switch ( sendPackets(test_socket, &req, &result) ) {
                        case -1:
                            /* Failed to write to socket */
                            goto errorCleanup;
                        case 1:
                            /* Bad test request, lets send a packet to keep the
                             * client happy it's still expecting something */
                            if ( sendFinalDataPacket(test_socket) < 0 ) {
                                goto errorCleanup;
                            }

                        case 0:
                        /* Success or our fake success from case 1: */
                        if ( !sockopts.disable_web10g ) {
                            web10g = getWeb10GSnap(test_socket);
                        }
                        /* Unlike old test, send result for either direction */
                        if ( sendResultPacket(control_socket, &result,
                                    web10g) < 0) {
                            goto errorCleanup;
                        }

                    }

                    if ( web10g != NULL ) {
                        free(web10g);
                    }
                    web10g = NULL;
                    memset(&req, 0, sizeof(req));
                    memset(&result, 0, sizeof(result));
                }
                continue;
            case TPUT_PKT_RENEW_CONNECTION:
                Log(LOG_INFO, "Client asked to renew the connection");

                /* Ready the listening socket again */
                sockopts.reuse_addr = 1;
                t_listen = startListening(sockopts.tport, &sockopts);
                if ( t_listen == -1 ) {
                    Log(LOG_ERR, "Failed to open listening socket terminating");
                    goto errorCleanup;
                }

                /* Finish this side of the TCP connection */
                shutdown(test_socket, SHUT_WR);
                /* Now the client has also closed */
                if ( readPacket(test_socket, &packet, NULL) != 0 ) {
                    Log(LOG_WARNING, "TPUT_NEW_CONNECTION expected the TCP connection to be closed in this direction");
                }
                close(test_socket);
                sendReadyPacket(control_socket, getSocketPort(t_listen));
                do {
                    test_socket = accept(t_listen,
                                  (struct sockaddr*) &client_addr, &client_addrlen);
                } while (test_socket == -1 && errno == EINTR);
                if ( test_socket == -1 ) {
                    Log(LOG_ERR, "Failed to accept after connection reset");
                    goto errorCleanup;
                }
                /* Close the listening socket again */
                close(t_listen);
                t_listen = -1;
                continue;
            case TPUT_PKT_CLOSE:
                Log(LOG_INFO, "Client closing test");
                break;
            default:
                Log(LOG_WARNING,
                        "serveTest() found a invalid packet.header.type %d",
                        (int) packet.header.type);
                /* Try and continue */
                continue;
            }
        break;
    }

    if ( test_socket != -1 ) {
        close(test_socket);
    }
    return 0;

errorCleanup:
    /*
     * This should kick off the client - we assume they are waiting for us
     * somewhere
     */
    if ( test_socket != -1 ) {
        close(test_socket);
    }
    if ( t_listen != -1 ) {
        close(t_listen);
    }
    if ( control_socket != -1 ) {
        close(control_socket);
    }
    if ( web10g != NULL ) {
        free(web10g);
    }
    return -1;
}



/**
 * The main function of the throughput server.
 */
void run_throughput_server(int argc, char *argv[], SSL *ssl) {
    int port; /* Port to start server on */
    int listen_socket; /* Our listening socket */
    int control_sock; /* Our clients control socket connection */
    int opt;
    struct opt_t sockopts;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;

    /* Possibly could use dests to limit interfaces to listen on */

    Log(LOG_DEBUG, "Running throughput test as server");

/*
    Log(LOG_DEBUG, "Our Structure sizes Pkt:%d RptHdr:%d RptRes:%d Rpt10G:%d",
            sizeof(struct packet_t),
            sizeof(struct report_header_t),
            sizeof(struct report_result_t),
            sizeof(struct report_web10g_t)
       );
*/

    /* set some sensible defaults */
    memset(&sockopts, 0, sizeof(sockopts));
    port = DEFAULT_CONTROL_PORT;
    sourcev4 = NULL;
    sourcev6 = NULL;
    device = NULL;

    /* TODO server should take long options too */
    while ( (opt = getopt(argc, argv, "?hp:4:6:I:")) != -1 ) {
        switch ( opt ) {
            case '4': sourcev4 = get_numeric_address(optarg); break;
            case '6': sourcev6 = get_numeric_address(optarg); break;
            case 'I': device = optarg; break;
            /* case 'B': for iperf compatability? */
            case 'p': port = atoi(optarg); break;
            case 'h':
            case '?':
            /* XXX do we need this extra usage statement here? */
            default: usage(argv[0]); exit(0);
        };
    }

    /* listen for a connection from a client */
    sockopts.reuse_addr = 1;
    if ( (listen_socket = startListening(port, &sockopts)) < 0 ) {
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

    client_addrlen = sizeof(client_addr);
    do {
        control_sock = accept(listen_socket, (struct sockaddr*) &client_addr,
                &client_addrlen);
    } while ( control_sock == -1 && errno == EINTR );

    /* Close the listening socket */
    close(listen_socket);

    if ( control_sock == -1 ) {
        Log(LOG_WARNING, "Failed to accept connection: %s", strerror(errno));
        return;
    }

    Log(LOG_DEBUG, "Got a client connection");

    serveTest(control_sock);
    close(control_sock);

    return;
}
