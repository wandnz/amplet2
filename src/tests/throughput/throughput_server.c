/**
 * The AMP throughput client, see the usage for details.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */

#include <getopt.h>

#include "throughput.h"


#if 0
#undef LOG_DEBUG
#define LOG_DEBUG LOG_WARNING
#endif

int run_throughput(int argc, char *argv[], int count, struct addrinfo **dests);
test_t *register_test(void);
void print_throughput(void *data, uint32_t len);



/**
 * Prints usage information
 */
static void usage(char *prog) {
    fprintf(stderr, "Usage: ./throughput-server [-p]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -p --port     The port number to listen on (default:%d)\n", DEFAULT_CONTROL_PORT);
    fprintf(stderr, " -h -? --help  Print this help\n");
    exit(0);
}

static struct option long_options[] =
    {
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
/*      {"c2s-time", required_argument, 0, 'T'},
        {"c2s-packet", required_argument, 0, 'Y'},
        {"s2c-time", required_argument, 0, 't'},
        {"s2c-packet", required_argument, 0, 'y'},
        {"pause", required_argument, 0, 'p'},
        {"new", required_argument, 0, 'N'},*/
        {NULL,0,0,0}
    };



/**
 * Start listening on the given port for incoming tests
 *
 * @param port
 *              The port to listen for incoming connections
 *
 * @return the bound listen_socket or return -1 if this fails
 */
static int startListening(int port, struct opt_t * sockopts) {
    int listen_socket = -1;
    struct addrinfo hints = {0};
    struct addrinfo *addrs, *current;
    char port_num[10] = "";
    int result;

    /* Get all interfaces and in order attempt to bind to them */
    hints.ai_family = AF_INET6;    /* Allow IPv6 note AI_V4MAPPED allows IPv4 I think ?? */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ALL;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    /* Have to make our port number a string for getaddrinfo() :( */
    snprintf(port_num, sizeof(port_num), "%d", port);

    /* The hint should give us a IPv6 and IPv4 binding if possible */
    result = getaddrinfo(NULL, port_num, &hints, &addrs);
    if ( result != 0 ) {
        Log(LOG_ERR, "getaddrinfo failed: %s", strerror(errno));
    }

    for ( current = addrs; current != NULL ; current = current->ai_next ) {

        /* Open a socket that we can listen on */
        listen_socket = socket(current->ai_family,
                            current->ai_socktype, current->ai_protocol);
        if ( listen_socket == -1 ) {
             Log(LOG_WARNING, "startListening failed to create a socket(): %s",
                     strerror(errno));
             continue;
        }
        /* Set socket options */
        doSocketSetup(sockopts, listen_socket);

        if ( bind(listen_socket, current->ai_addr, current->ai_addrlen) == 0) {
            break; /* successfully bound*/
        }

        /* State of socket is unknown after a failed bind() */
        close(listen_socket);
        listen_socket = -1;
    }

    freeaddrinfo(addrs);

    if ( listen_socket == -1 ) {
        Log(LOG_ERR, "startListening failed to bind the listening socket");
        goto errorCleanup;
    }

    /* Start listening for at most 1 connection, we don't want a huge queue */
    if (listen(listen_socket, 1) == -1) {
        Log(LOG_ERR, "startListening failed to listen on our bound socket: %s",
                strerror(errno));
        goto errorCleanup;
    }

    Log(LOG_DEBUG, "Successfully listening on port %s", port_num);
    return listen_socket;

    errorCleanup:
    if ( listen_socket != -1 ) {
        close(listen_socket);
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
    struct report_web10g_t * web10g = NULL;
    struct opt_t sockopts = {0};
    int t_listen;
    int test_socket;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    uint32_t version = 0;

    memset(&packet, 0, sizeof(packet));
    memset(&result, 0, sizeof(result));

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

    do{
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
                if ( sendResultPacket(control_socket, &result, web10g) != 0 ) {
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
                    req.packets = packet.types.send.packets;
                    req.duration = packet.types.send.duration_ms;
                    req.packet_size = packet.types.send.packet_size;
                    req.randomise = sockopts.randomise;
                    Log(LOG_INFO, "Got send request for pkts:%d dur:%d size:%d",
                            req.packets,req.duration, req.packet_size);

                    /* Send the actual packets */
                    switch ( sendPackets(test_socket, &req, &result) ) {
                        case -1:
                            /* Failed to write to socket */
                            goto errorCleanup;
                        case 1:
                            /* Bad test request, lets send a packet to keep the
                             * client happy it's still expecting something */
                            if ( sendFinalDataPacket(test_socket) != 0 ) {
                                goto errorCleanup;
                            }

                        case 0:
                        /* Success or our fake success from case 1: */
                        if ( !sockopts.disable_web10g ) {
                            web10g = getWeb10GSnap(test_socket);
                        }
                        /* Unlike old test, send result for either direction */
                        if ( sendResultPacket(control_socket, &result,
                                    web10g) != 0) {
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
    /* This should kick off the client - we assume they are waiting for us somewhere */
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
int run_throughput(int argc, char *argv[], int count, struct addrinfo **dests) {
    int port; /* Port to start server on */
    int listen_socket; /* Our listening socket */
    int control_sock; /* Our clients control socket connection */
    int opt; /* Used by getopt() */
    struct opt_t sockopts = {0};
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;

    /* Possibly could use dests to limit interfaces to listen on */

    Log(LOG_DEBUG, "Starting throughput server got given %d addresses", count);
    Log(LOG_INFO, "Our Structure sizes Pkt:%d RptHdr:%d RptRes:%d Rpt10G:%d",
            sizeof(struct packet_t),
            sizeof(struct report_header_t),
            sizeof(struct report_result_t),
            sizeof(struct report_web10g_t)
       );

    /* set some sensible defaults */
    port = DEFAULT_CONTROL_PORT;

    while ( (opt = getopt(argc, argv, "?hp:")) != -1 ) {
        switch ( opt ) {
            case 'p': port = atoi(optarg); break;
            case 'h':
            case '?':
            default: usage(argv[0]); exit(0);
        };
    }

    /* listen for a connection from a client */
    sockopts.reuse_addr = 1;
    listen_socket = startListening(port, &sockopts);

    if ( listen_socket == -1 ) {
        Log(LOG_ERR, "Failed to open listening socket terminating");
        return -1;
    }

    client_addrlen = sizeof(client_addr);
    do{
        control_sock = accept(listen_socket,
                      (struct sockaddr*) &client_addr, &client_addrlen);
    } while ( control_sock == -1 && errno == EINTR );

    /* Close the listening socket */
    close(listen_socket);
    listen_socket = -1;

    if ( control_sock == -1 ) {
        Log(LOG_WARNING, "Failed to connect() upon our listening socket: %s",
                strerror(errno));
    } else {
        Log(LOG_DEBUG, "Successfully got a client connection I Should do something");
        serveTest(control_sock);
    }

    close(control_sock);
    control_sock = -1;

    return 0;
}



/*
 * DOES NOTHING, Client reports results
 */
void print_throughput(void *data, uint32_t len) {
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_THROUGHPUT;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("throughput");

    /* how many targets a single instance of this test can have  - Only 1 */
    new_test->max_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_throughput;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_throughput;

    return new_test;
}
