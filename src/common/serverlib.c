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


//XXX remove unused includes
#include "testlib.h"
#include "debug.h"
#include "tests.h"
#include "modules.h"
#include "messaging.h"
#include "ssl.h"
#include "global.h"
#include "serverlib.h"
#include "controlmsg.h"
#include "measured.pb-c.h"



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
static void do_socket_setup(struct sockopt_t *options, int sock, int family) {

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

    if ( options->dscp ) {
        struct socket_t sockets;
        /* wrap the socket in a socket_t so we can call other amp functions */
        memset(&sockets, 0, sizeof(sockets));
        switch ( family ) {
            case AF_INET: sockets.socket = sock; break;
            case AF_INET6: sockets.socket6 = sock; break;
            default: Log(LOG_ERR,"Unknown address family %d when setting DSCP",
                             family);
                     return;
        };

        if ( set_dscp_socket_options(&sockets, options->dscp) < 0 ) {
            Log(LOG_ERR, "Failed to set DSCP socket options");
            return;
        }
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
        do_socket_setup(sockopts, sockets->socket, AF_INET);
        ((struct sockaddr_in*)
         (sockopts->sourcev4->ai_addr))->sin_port = ntohs(port);
    }

    if ( sockets->socket6 >= 0 ) {
        int one = 1;
        do_socket_setup(sockopts, sockets->socket6, AF_INET6);
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
 * XXX this function is a mess, so much duplication with others and it's only
 * used by the throughput test. Can we fix it?
 */
int connect_to_server(struct addrinfo *server, struct sockopt_t *options,
        int port) {

    int sock;

    sock = socket(server->ai_family, options->socktype, options->protocol);

    if ( sock < 0 ) {
        Log(LOG_WARNING, "Failed to create control socket:%s", strerror(errno));
        return -1;
    }

    do_socket_setup(options, sock, server->ai_family);

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



/*
 *
 */
static int send_server_start(BIO *ctrl, test_type_t type) {
    int len;
    void *buffer;
    int result;
    Amplet2__Measured__Control msg = AMPLET2__MEASURED__CONTROL__INIT;
    Amplet2__Measured__Server server = AMPLET2__MEASURED__SERVER__INIT;

    server.has_test_type = 1;
    server.test_type = type;

    msg.server = &server;
    msg.has_type = 1;
    msg.type = AMPLET2__MEASURED__CONTROL__TYPE__SERVER;

    len = amplet2__measured__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__measured__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 *
 */
void close_control_connection(BIO *ctrl) {
    Log(LOG_DEBUG, "Closing control connection");

    if ( !ctrl ) {
        Log(LOG_WARNING, "Tried to close NULL control connection");
        return;
    }

    BIO_free_all(ctrl);
}



/*
 *
 */
BIO* listen_control_server(uint16_t port, uint16_t portmax,
        struct sockopt_t *sockopts) {

    struct socket_t listen_sockets;
    int control_sock;
    int family;
    BIO *ctrl;
    int res;
    int maxwait = MAXIMUM_SERVER_WAIT_TIME;

    do {
        Log(LOG_DEBUG, "test control server trying to listen on port %d", port);
        //XXX pass a hints type struct?
        res = start_listening(&listen_sockets, port, sockopts);
    } while ( res == EADDRINUSE && port++ < portmax );

    if ( res != 0 ) {
        Log(LOG_ERR, "Failed to open listening control socket terminating");
        return NULL;
    }

    if ( (family = wait_for_data(&listen_sockets, &maxwait)) <= 0 ) {
        Log(LOG_DEBUG, "Timeout out waiting for control connection");
        return NULL;
    }

    switch ( family ) {
        case AF_INET:
            control_sock = accept(listen_sockets.socket, NULL, NULL);
            Log(LOG_DEBUG, "Got control connection on IPv4");
            /* clear out v6 address, it isn't needed any more */
            freeaddrinfo(sockopts->sourcev6);
            sockopts->sourcev6 = NULL;
            /* set v4 address to our local endpoint address */
            freeaddrinfo(sockopts->sourcev4);
            sockopts->sourcev4 = get_socket_address(control_sock);
            break;

        case AF_INET6:
            control_sock = accept(listen_sockets.socket6, NULL, NULL);
            Log(LOG_DEBUG, "Got control connection on IPv6");
            /* clear out v4 address, it isn't needed any more */
            freeaddrinfo(sockopts->sourcev4);
            sockopts->sourcev4 = NULL;
            /* set v6 address to our local endpoint address */
            freeaddrinfo(sockopts->sourcev6);
            sockopts->sourcev6 = get_socket_address(control_sock);
            break;

        default: return NULL;
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
        return NULL;
    }

    if ( (ctrl = establish_control_socket(ssl_ctx, control_sock, 0)) == NULL ) {
        Log(LOG_WARNING, "Failed to establish control connection");
        return NULL;
    }

    return ctrl;
}



/*
 * TODO apart from SSL stuff, this is very similar to the function used for
 * connecting test sockets.
 */
BIO* connect_control_server(struct addrinfo *dest, uint16_t port,
        amp_test_meta_t *meta) {

    BIO *ctrl;
    int res;
    int attempts;
    int sock;

    assert(dest);
    assert(dest->ai_addr);

    Log(LOG_DEBUG, "Connecting to control socket tcp/%d on remote server",port);

    /* set the port number in the destination addrinfo */
    switch ( dest->ai_family ) {
        case AF_INET: ((struct sockaddr_in *)dest->ai_addr)->sin_port =
                          htons(port);
                      break;
        case AF_INET6: ((struct sockaddr_in6 *)dest->ai_addr)->sin6_port =
                           htons(port);
                       break;
        default: return NULL;
    };

    /* Create the socket */
    if ( (sock = socket(dest->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        Log(LOG_DEBUG, "Failed to create socket");
        return NULL;
    }

    /* bind to a local interface if specified */
    if ( meta && meta->interface ) {
        if ( bind_socket_to_device(sock, meta->interface) < 0 ) {
            return NULL;
        }
    }

    /* bind to a local address if specified */
    if ( meta && (meta->sourcev4 || meta->sourcev6) ) {
        struct addrinfo *addr;

        switch ( dest->ai_family ) {
            case AF_INET: addr = get_numeric_address(meta->sourcev4, NULL);
                          break;
            case AF_INET6: addr = get_numeric_address(meta->sourcev6, NULL);
                           break;
            default: return NULL;
        };

        /*
         * Only bind if we have a specific source with the same address
         * family as the destination, otherwise leave it default.
         */
        if ( addr ) {
            int res;
            res = bind_socket_to_address(sock, addr);
            freeaddrinfo(addr);
            if ( res < 0 ) {
                return NULL;
            }
        }
    }

    /* Try a few times to connect, but give up after failing too many times */
    attempts = 0;
    do {
        if ( (res = connect(sock, dest->ai_addr, dest->ai_addrlen)) < 0 ) {
            char addrstr[INET6_ADDRSTRLEN];
            attempts++;

            /*
             * The destination is from our nametable, so it should have a
             * useful canonical name set, we aren't relying on getaddrinfo.
             */
            Log(LOG_DEBUG,
                    "Failed to connect to %s:%d (%s:%d) attempt %d/%d: %s",
                    dest->ai_canonname, port,
                    amp_inet_ntop(dest, addrstr), port, attempts,
                    MAX_CONNECT_ATTEMPTS, strerror(errno));

            if ( attempts >= MAX_CONNECT_ATTEMPTS ) {
                Log(LOG_WARNING,
                        "Failed too many times connecting to %s:%d (%s:%d)",
                        dest->ai_canonname, port, amp_inet_ntop(dest, addrstr),
                        port);
                return NULL;
            }

            /*
             * Don't bother with exponential backoff or similar, just try a
             * few times in case something funny is going on, then give up.
             * XXX is it actually worth trying more than once? Are there
             * error codes that should cause us just to stop immediately?
             * Or any error codes that we know are only temporary? How long
             * should we keep trying for until it becomes not worth it, because
             * we are no longer at the time our test was scheduled?
             */
            Log(LOG_DEBUG, "Waiting %d seconds before trying again",
                    CONTROL_CONNECT_DELAY);
            sleep(CONTROL_CONNECT_DELAY);
        }
    } while ( res < 0 );

    ctrl = establish_control_socket(ssl_ctx, sock, 1);

    /* if there is an SSL context then we are expected to use SSL */
    //XXX should this happen in connect? except we don't know destination
    if ( ssl_ctx ) {
        X509 *server_cert;
        SSL *ssl;

        /* Open up the ssl channel and validate the cert against our CA cert */
        /* TODO CRL or OCSP to deal with revocation of certificates */
        BIO_get_ssl(ctrl, &ssl);

        /* Recover the server's certificate */
        server_cert = SSL_get_peer_certificate(ssl);
        if ( server_cert == NULL ) {
            Log(LOG_DEBUG, "Failed to get peer certificate");
            BIO_free_all(ctrl);
            return NULL;
        }

        /* Validate the hostname */
        if ( matches_common_name(dest->ai_canonname, server_cert) != 0 ) {
            Log(LOG_DEBUG, "Hostname validation failed");
            X509_free(server_cert);
            BIO_free_all(ctrl);
            return NULL;
        }

        X509_free(server_cert);

        Log(LOG_DEBUG, "Successfully validated cert, connection established");
    } else {
        Log(LOG_DEBUG, "No SSL context, using plain control connection");
    }

    return ctrl;
}



/*
 * Ask that a remote amplet client that we are connected to start a server
 * for a particular test.
 */
int start_remote_server(BIO *ctrl, test_type_t type) {

    assert(ctrl);
    assert(type > AMP_TEST_INVALID && type < AMP_TEST_LAST);

    /* Send the test type, so the other end knows which server to run */
    /* TODO send any test parameters? */
    if ( send_server_start(ctrl, type) < 0 ) {
        Log(LOG_DEBUG, "Failed to send test type");
        return -1;
    }

    return 0;
}
