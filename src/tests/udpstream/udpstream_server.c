#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include "tests.h"
#include "serverlib.h"
#include "testlib.h"
#include "udpstream.h"
#include "servers.pb-c.h"



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
    struct addrinfo client;
    struct opt_t options;
    void *data;
    struct timeval *times = NULL;
    Amplet2__Udpstream__Item *result;
    ProtobufCBinaryData packed;

    if ( read_control_hello(control_sock, sockopts) < 0 ) {
        Log(LOG_WARNING, "Got bad HELLO packet, shutting down test server");
        return -1;
    }

    options.packet_size = sockopts->packet_size;//XXX
    options.packet_count = sockopts->packet_count;//XXX
    options.packet_spacing = sockopts->packet_spacing;//XXX
    options.percentile_count = sockopts->percentile_count;//XXX

    /*
     * Try to create the test server on the appropriate port. If test port has
     * been manually set, only try that port. If it is still the default, try
     * a few ports till we hopefully find a free one.
     */
    if ( sockopts->tport == DEFAULT_TEST_PORT ) {
        portmax = MAX_TEST_PORT;
    } else {
        if ( sockopts->tport < IPPORT_RESERVED ) {
            Log(LOG_WARNING, "Not allowing test ports < 1024");
            return -1;
        }
        portmax = sockopts->tport;
    }

    /* configure the new UDP test socket */
    sockopts->socktype = SOCK_DGRAM;
    sockopts->protocol = IPPROTO_UDP;
    if ( remote->ss_family == AF_INET ) {
        sockopts->sourcev6 = NULL;
    } else {
        sockopts->sourcev4 = NULL;
    }

    /* No errors so far, make our new test socket with the given test options */
    do {
        res = start_listening(&sockets, sockopts->tport, sockopts);
    } while ( res == EADDRINUSE && sockopts->tport++ < portmax );

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

    //XXX this is all only used when sending
    client.ai_flags = 0;
    client.ai_family = remote->ss_family;
    client.ai_socktype = SOCK_DGRAM;
    client.ai_protocol = IPPROTO_UDP;
    client.ai_addr = (struct sockaddr*)remote;
    if ( client.ai_family == AF_INET ) {
        client.ai_addrlen = sizeof(struct sockaddr_in);
    } else {
        client.ai_addrlen = sizeof(struct sockaddr_in6);
    }
    client.ai_canonname = NULL;
    client.ai_next = NULL;

    while ( (bytes=read_control_packet(control_sock, &data)) > 0 ) {
        Amplet2__Servers__Control *msg;
        msg = amplet2__servers__control__unpack(NULL, bytes, data);

        switch ( msg->type ) {
            case AMPLET2__SERVERS__CONTROL__TYPE__SEND:
                /* send the data stream to the client on the port specified */
                printf("got SEND command with port %d\n", msg->send->test_port);
                //XXX parse_control_ready or just use it?
                //XXX at least check it's valid etc...
                //if ( parse_control_send(data, bytes, sockopts) < 0 ) {
                //    return -1;
                //}

                // XXX client.ai_addr points at this, maybe should update that
                // directly so it is obvious?
                ((struct sockaddr_in*)remote)->sin_port = ntohs(msg->send->test_port);
                send_udp_stream(test_sock, &client, &options);
                break;

            case AMPLET2__SERVERS__CONTROL__TYPE__RECEIVE:
                printf("got receive packet\n");
                //XXX parse function takes inconsistent args
                //XXX unpacked vs packed
                if ( parse_control_receive(data, bytes, sockopts) < 0 ) {
                    return -1;
                }
                /* tell the client what port the test server is running on */
                send_control_ready(control_sock, sockopts->tport);
                /* wait for the data stream from the client */
                times = calloc(sockopts->packet_count, sizeof(struct timeval));
                receive_udp_stream(test_sock, sockopts->packet_count, times);
                result = report_stream(UDPSTREAM_TO_SERVER, times, &options);
                /* pack the result for sending to the client */
                packed.len = amplet2__udpstream__item__get_packed_size(result);
                packed.data = malloc(packed.len);
                amplet2__udpstream__item__pack(result, packed.data);
                send_control_result(control_sock, &packed);
                free(times);
                free(result);
                free(packed.data);
                break;

            default: Log(LOG_WARNING, "Unhandled message type %d\n", msg->type);
                     break;
        };

        /* both read_control_packet and unpacking the buffer allocate memory */
        free(data);
        amplet2__servers__control__free_unpacked(msg, NULL);
    }

    close(test_sock);

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
                      //XXX does the throughput test need this?
                      /* clear out the v6 address, it isn't needed any more */
                      //freeaddrinfo(sockopts.sourcev6);
                      //sockopts.sourcev6 = NULL;
                      /* set v4 address to where we received the connection */
                      //freeaddrinfo(sockopts.sourcev4);
                      //sockopts.sourcev4 = getSocketAddress(control_sock);
                      break;

        case AF_INET6: control_sock = accept(listen_sockets.socket6,
                              (struct sockaddr*)&client_addr, &client_addrlen);
                      Log(LOG_DEBUG, "Got control connection on IPv6");
                      //XXX does the throughput test need this?
                      /* clear out the v4 address, it isn't needed any more */
                      //freeaddrinfo(sockopts.sourcev4);
                      //sockopts.sourcev4 = NULL;
                      /* set v6 address to where we received the connection */
                      //freeaddrinfo(sockopts.sourcev6);
                      //sockopts.sourcev6 = getSocketAddress(control_sock);
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
        //free(sockopts.sourcev4->ai_addr);
        //free(sockopts.sourcev4);
        freeaddrinfo(sockopts.sourcev4);
        sockopts.sourcev4 = NULL;
        freeaddrinfo(sockopts.sourcev6);
        sockopts.sourcev6 = NULL;
    }

    if ( sockopts.sourcev6 ) {
        //free(sockopts.sourcev6->ai_addr);
        //free(sockopts.sourcev6);
        freeaddrinfo(sockopts.sourcev4);
        sockopts.sourcev4 = NULL;
        freeaddrinfo(sockopts.sourcev6);
        sockopts.sourcev6 = NULL;
    }

    return;
}
