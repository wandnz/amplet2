/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Authors: Richard Sanger
 *          Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

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
 * Notify the remote end that we are ready to receive test data, receive the
 * stream of test data, then send back results from our side of the connection.
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



/*
 * Send a stream of test data, then send back results from our side of the
 * test connection.
 */
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
    switch ( sendStream(test_sock, request, &result) ) {
        case -1:
            /* Failed to write to socket */
            return -1;

        case 0:
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



/*
 * Close and reopen the test connection. In some cases this will have the
 * effect of resetting various TCP congestion variables, though this is
 * perhaps becoming less common.
 */
static int do_renew(BIO *ctrl, int test_sock, uint16_t port, uint16_t portmax,
        struct sockopt_t *sockopts) {

    struct socket_t sockets;
    int t_listen;
    int res;

    Log(LOG_DEBUG, "Client asked to renew the connection");

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

    return test_sock;
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

    /* set the options that we don't know until the remote end tells us */
    sockopts->dscp = options->dscp;//XXX

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

                close(test_sock);
                test_sock = -1;

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

                close(test_sock);
                test_sock = -1;
                free(request);

                break;
            }

            case AMPLET2__CONTROLMSG__CONTROL__TYPE__RENEW: {

                if ( (test_sock = do_renew(ctrl, test_sock, options->tport,
                            portmax, sockopts)) < 0 ) {
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
    extern struct option long_options[];
    uint16_t portmax;
    int standalone;

    /* Possibly could use dests to limit interfaces to listen on */

    Log(LOG_DEBUG, "Running throughput test as server");

    /* set some sensible defaults */
    memset(&sockopts, 0, sizeof(sockopts));
    port = DEFAULT_CONTROL_PORT;
    portmax = MAX_CONTROL_PORT;
    standalone = 0;

    while ( (opt = getopt_long(argc, argv, "p:I:Q:Z:4:6:hx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4': sockopts.sourcev4 = get_numeric_address(optarg, NULL);
                      break;
            case '6': sockopts.sourcev6 = get_numeric_address(optarg, NULL);
                      break;
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

    Log(LOG_DEBUG, "Throughput server port=%d, maxport=%d", port, portmax);

    /*
     * We currently need the addrinfo structs to exist so we can set the port
     * number for the server to listen on, so create them if they don't exist.
     */
    if ( sockopts.sourcev4 == NULL ) {
        sockopts.sourcev4 = get_numeric_address("0.0.0.0", NULL);
    }
    if ( sockopts.sourcev6 == NULL ) {
        sockopts.sourcev6 = get_numeric_address("::", NULL);
    }
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

        /* we made the control connection ourselves, so close it up again */
        close_control_connection(ctrl);
    } else {
        /* addrinfo structs were done properly using getaddrinfo */
        if ( sockopts.sourcev4 ) {
            freeaddrinfo(sockopts.sourcev4);
        }

        if ( sockopts.sourcev6 ) {
            freeaddrinfo(sockopts.sourcev6);
        }
    }

    return;
}
