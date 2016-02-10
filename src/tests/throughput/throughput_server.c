/**
 * The AMP throughput client, see the usage for details.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */

#include <getopt.h>
#include <assert.h>

#include "serverlib.h"
#include "throughput.h"
#include "servers.pb-c.h"



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
 * Return the local address that the socket is using.
 */
static struct addrinfo *getSocketAddress(int sock_fd) {
    struct addrinfo *addr;

    assert(sock_fd > 0);

    /* make our own struct addrinfo */
    addr = (struct addrinfo *)malloc(sizeof(struct addrinfo));
    addr->ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_storage));
    addr->ai_addrlen = sizeof(struct sockaddr_storage);

    /* ask to fill in the ai_addr portion for our socket */
    getsockname(sock_fd, addr->ai_addr, &addr->ai_addrlen);

    /* we already know most of the rest, so fill that in too */
    addr->ai_family = ((struct sockaddr*)addr->ai_addr)->sa_family;
    addr->ai_socktype = SOCK_STREAM;
    addr->ai_protocol = IPPROTO_TCP;
    addr->ai_canonname = NULL;
    addr->ai_next = NULL;

    return addr;
}



/**
 * Serves a test for a connected client
 *
 * @param server_address Address of the server to connect to and run the test
 * @param options A copy of the program options which also contains the sequence
 *
 * @return 0 if successful, -1 upon error.
 */
static int serveTest(int control_socket, struct temp_sockopt_t_xxx *sockopts) {
    struct packet_t packet;
    struct test_result_t result;
    int bytes;
    struct report_web10g_t *web10g = NULL;
    int t_listen = -1;
    int test_socket = -1;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    struct socket_t sockets;
    uint16_t portmax;
    int res;
    void *data;

    memset(&packet, 0, sizeof(packet));
    memset(&result, 0, sizeof(result));

    /* Read the hello and check we are compatible */
    if ( read_control_hello(control_socket, sockopts) < 0 ) {
        goto errorCleanup;
    }

    /* If test port has been manually set, only try that port. If it is
     * still the default, try a few ports till we hopefully find a free one.
     */
    if ( sockopts->tport == DEFAULT_TEST_PORT ) {
        portmax = MAX_TEST_PORT;
    } else {
        portmax = sockopts->tport;
    }

    /* No errors so far, make our new testsocket with the given test options */
    do {
        res = start_listening(&sockets, sockopts->tport, sockopts);
    } while ( res == EADDRINUSE && sockopts->tport++ < portmax );

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
    send_control_ready(control_socket, getSocketPort(t_listen));

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
    while ( (bytes=read_control_packet(control_socket, &data)) > 0 ) {
        Amplet2__Servers__Control *msg;
        msg = amplet2__servers__control__unpack(NULL, bytes, data);

        switch ( msg->type ) {
            case AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE:
                /* Send READY here so timestamp is accurate */
                send_control_ready(control_socket, 0);
                if ( incomingTest(test_socket, &result) != 0 ) {
                    goto errorCleanup;
                }

                if ( !sockopts->disable_web10g ) {
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

            case AMPLET2__SERVERS__CONTROL__TYPE__SEND:
                {
                    struct test_request_t req;
                    memset(&req, 0, sizeof(req));
                    memset(&result, 0, sizeof(result));
                    req.duration = msg->send->duration_ms;
                    req.write_size = msg->send->write_size;
                    req.bytes = msg->send->bytes;
                    req.randomise = sockopts->randomise;
                    Log(LOG_DEBUG, "Got send request, dur:%d bytes:%d writes:%d",
                            req.duration, req.bytes, req.write_size);

                    /* Send the actual packets */
                    switch ( sendPackets(test_socket, &req, &result) ) {
                        case -1:
                            /* Failed to write to socket */
                            goto errorCleanup;
                        case 1:
                            /* Bad test request, lets send a packet to keep the
                             * client happy it's still expecting something.
                             * XXX Why do it like this?
                             */
                            if ( send_control_receive(test_socket, 0) < 0 ) {
                                goto errorCleanup;
                            }

                        case 0:
                        /* Success or our fake success from case 1: */
                        if ( !sockopts->disable_web10g ) {
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

            case AMPLET2__SERVERS__CONTROL__TYPE__RENEW:
                Log(LOG_DEBUG, "Client asked to renew the connection");

                /* Ready the listening socket again */
                do {
                    res = start_listening(&sockets, sockopts->tport, sockopts);
                } while ( res == EADDRINUSE && sockopts->tport++ < portmax );

                if ( res != 0 ) {
                    Log(LOG_ERR, "Failed to open listening socket terminating");
                    goto errorCleanup;
                }

                if ( sockets.socket > 0 ) {
                    t_listen = sockets.socket;
                } else {
                    t_listen = sockets.socket6;
                }

                /* Finish this side of the TCP connection */
                shutdown(test_socket, SHUT_WR);
                /* Now the client has also closed */
                if ( readPacket(test_socket, &packet, NULL) != 0 ) {
                    Log(LOG_WARNING, "TPUT_NEW_CONNECTION expected the TCP connection to be closed in this direction");
                }
                close(test_socket);
                send_control_ready(control_socket, getSocketPort(t_listen));
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

            case AMPLET2__SERVERS__CONTROL__TYPE__CLOSE:
                Log(LOG_DEBUG, "Client closing test");
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
    struct socket_t listen_sockets;
    int control_sock; /* Our clients control socket connection */
    int opt;
    struct temp_sockopt_t_xxx sockopts;//XXX WRONG
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

    /* try to open a listen port for the control connection from a client */
    do {
        Log(LOG_DEBUG, "Throughput server trying to listen on port %d", port);
        res = start_listening(&listen_sockets, port, &sockopts);
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
    maxwait = 60000000; /* XXX 60s, how long should this be? */
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
                      sockopts.sourcev4 = getSocketAddress(control_sock);
                      break;

        case AF_INET6: control_sock = accept(listen_sockets.socket6,
                              (struct sockaddr*)&client_addr, &client_addrlen);
                      Log(LOG_DEBUG, "Got control connection on IPv6");
                      /* clear out the v4 address, it isn't needed any more */
                      freeaddrinfo(sockopts.sourcev4);
                      sockopts.sourcev4 = NULL;
                      /* set v6 address to where we received the connection */
                      freeaddrinfo(sockopts.sourcev6);
                      sockopts.sourcev6 = getSocketAddress(control_sock);
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
    serveTest(control_sock, &sockopts);
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
