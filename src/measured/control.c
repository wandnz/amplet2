/*
 * src/measured/control.c
 * Accept connections from remote amplets and run test servers.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <libwandevent.h>

#include "debug.h"
#include "control.h"
#include "watchdog.h"
#include "modules.h"
#include "testlib.h"
#include "global.h"
#include "ssl.h"


/*
 * Create the control socket and start it listening for connections. We
 * use separate sockets for IPv4 and IPv6 so that we can have each of them
 * listening on specific, different addresses.
 */
int initialise_control_socket(struct socket_t *sockets, char *iface,
        char *ipv4, char* ipv6, char *port) {

    struct addrinfo *addr4, *addr6;
    int one = 1;
    char addrstr[INET6_ADDRSTRLEN];

    Log(LOG_DEBUG, "Creating control socket");

    assert(sockets);
    sockets->socket = -1;
    sockets->socket6 = -1;

    addr4 = get_numeric_address(ipv4, port);
    addr6 = get_numeric_address(ipv6, port);

    if ( (sockets->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        Log(LOG_WARNING, "Failed to open IPv4 control socket: %s",
                strerror(errno));
    }
    if ( (sockets->socket6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        Log(LOG_WARNING, "Failed to open IPv6 control socket: %s",
                strerror(errno));
    }

    /* make sure that at least one of them was opened ok */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
        return -1;
    }

    /* set socket options */
    if ( sockets->socket > 0 ) {
        if ( setsockopt(sockets->socket, SOL_SOCKET, SO_REUSEADDR, &one,
                    sizeof(int)) < 0 ) {
            close(sockets->socket);
            sockets->socket = -1;
        }
    }

    if ( sockets->socket6 > 0 ) {
        /* IPV6_V6ONLY prevents it trying to listen on IPv4 as well */
        if ( setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_V6ONLY, &one,
                    sizeof(one)) < 0 ) {
            close(sockets->socket6);
            sockets->socket6 = -1;
        } else {
            if ( setsockopt(sockets->socket6, SOL_SOCKET, SO_REUSEADDR, &one,
                        sizeof(int)) < 0 ) {
                close(sockets->socket6);
                sockets->socket6 = -1;
            }
        }
    }

    /* bind them to interfaces and addresses if required */
    if ( iface && bind_sockets_to_device(sockets, iface) < 0 ) {
        Log(LOG_ERR, "Unable to bind sockets to device, aborting test");
        return -1;
    }

    if ( bind_sockets_to_address(sockets, addr4, addr6) < 0 ) {
        Log(LOG_ERR,"Unable to bind socket to address, aborting test");
        return -1;
    }

    /* Start listening for control connections on the active sockets */
    if ( sockets->socket > 0 ) {
        if ( listen(sockets->socket, 16) < 0 ) {
            Log(LOG_WARNING, "Failed to listen on IPv4 control socket: %s",
                    strerror(errno));
            close(sockets->socket);
            sockets->socket = -1;
        }
    }

    if ( sockets->socket6 > 0 ) {
        if ( listen(sockets->socket6, 16) < 0 ) {
            Log(LOG_WARNING, "Failed to listen on IPv6 control socket: %s",
                    strerror(errno));
            close(sockets->socket6);
            sockets->socket6 = -1;
        }
    }

    /* make sure that at least one of them is listening ok */
    if ( sockets->socket < 0 && sockets->socket6 < 0 ) {
        return -1;
    }

    if ( sockets->socket > 0 ) {
        Log(LOG_INFO, "Control socket listening on %s:%s",
                amp_inet_ntop(addr4, addrstr), port);
    }

    if ( sockets->socket6 > 0 ) {
        Log(LOG_INFO, "Control socket listening on %s:%s",
                amp_inet_ntop(addr6, addrstr), port);
    }

    freeaddrinfo(addr4);
    freeaddrinfo(addr6);
    return 0;
}



/*
 *
 */
static void process_control_message(int fd, test_t *test) {
    SSL *ssl;
    X509 *client_cert;
    struct sockaddr_storage peer;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    char hostname[NI_MAXHOST];

    assert(test);
    assert(test->server_callback);

    Log(LOG_DEBUG, "Processing control message");

    /*
     * Get the name of the remote end before we even try to do anything SSL
     * related - if we can't get the hostname we won't be able to validate
     * it anyway.
     */
    if ( getpeername(fd, (struct sockaddr *)&peer, &addrlen) < 0 ) {
        Log(LOG_WARNING, "Failed to get peer");
        close(fd);
        exit(0);
    }

    if ( getnameinfo((struct sockaddr *)&peer, addrlen, hostname, NI_MAXHOST,
                NULL, 0, NI_NAMEREQD) < 0 ) {
        Log(LOG_WARNING, "Failed to resolve peer hostname");
        close(fd);
        exit(0);
    }

    Log(LOG_DEBUG, "Remote host is named %s", hostname);

    /* Open up the ssl channel and validate the cert against our CA cert */
    /* TODO CRL or OCSP to deal with revocation of certificates */
    if ( (ssl = ssl_accept(ssl_ctx, fd)) == NULL ) {
        close(fd);
        exit(0);
    }

    /* Get the peer certificate so we can validate it */
    client_cert = SSL_get_peer_certificate(ssl);
    if ( client_cert == NULL ) {
        Log(LOG_WARNING, "Failed to get peer certificate");
        ssl_shutdown(ssl);
        close(fd);
        exit(0);
    }

    /*
     * XXX turn this off for now, as relying on reverse DNS doesn't actually
     * add a lot of useful security, and we don't have control over how it
     * is set for most of our monitors. For now, we will accept a control
     * connection from anyone that has a valid cert, as there doesn't appear
     * to be anything too bad they can do (i.e. use us to attack others).
     */
#if 0
    /* Validate that the client hostname matches the common name in the cert */
    if ( matches_common_name(hostname, client_cert) != 0 ) {
        Log(LOG_DEBUG, "Closing control connection to unverified client");
        X509_free(client_cert);
        ssl_shutdown(ssl);
        close(fd);
        Log(LOG_DEBUG, "Terminating control process, pid: %d", getpid());
        exit(0);
    }
#endif

    Log(LOG_DEBUG, "Successfully validated peer cert");

    /* TODO read test arguments if required */

    /*
     * Run server function using callback in test, give it the ssl descriptor
     * so that it can report the port number.
     */
    test->server_callback(0, NULL, ssl);

    X509_free(client_cert);
    ssl_shutdown(ssl);
    close(fd);
    exit(0);
}



/*
 * Read initial data from a control connection and stop triggering on this
 * socket. The first byte will be a test id that we need to validate and will
 * be used to set up watchdogs. After forking, that process will take care of
 * validating the SSL certs and actually running the server.
 */
static void control_read_callback(wand_event_handler_t *ev_hdl, int fd,
        __attribute__((unused))void *data,
        __attribute__((unused))enum wand_eventtype_t ev) {

    uint8_t test_id;
    test_t *test;
    pid_t pid;

    /*
     * The main event loop shouldn't trigger on these events any more, once
     * we read data from here it is someone elses problem.
     */
    wand_del_fd(ev_hdl, fd);

    /* Read the first byte to get the test id. We will trust this value for
     * now, before we verify the SSL certificate - there isn't much harm that
     * can come from it, and if it is bogus we bail out very quickly.
     */
    if ( recv(fd, &test_id, sizeof(uint8_t), 0) < 0 ) {
        /* Failed to read the test id, close connection and remove event */
        close(fd);
        return;
    }

    Log(LOG_DEBUG, "Read test id %d from control connection", test_id);

    /* Make sure it is a valid test id we are being asked to start */
    if ( test_id >= AMP_TEST_LAST || test_id <= AMP_TEST_INVALID ) {
        Log(LOG_DEBUG, "Read invalid test id on control socket: %d", test_id);
        close(fd);
        return;
    }

    /* TODO limit number of connections/servers running, weighted system */

    /* Make sure that the test has been built and loaded */
    if ( (test = amp_tests[test_id]) == NULL ) {
        Log(LOG_DEBUG, "No test module for test id: %d", test_id);
        close(fd);
        return;
    }

    /* Make sure that the test requires a server to be run */
    if ( test->server_callback == NULL ) {
        Log(LOG_DEBUG, "No server callback for %s test", test->name);
        close(fd);
        return;
    }

    /* Fork to validate SSL cert and actually run the server */
    if ( (pid = fork()) < 0 ) {
        Log(LOG_WARNING, "Failed to fork for control connection: %s",
                strerror(errno));
        return;
    } else if ( pid == 0 ) {
        process_control_message(fd, test);
        assert(0);
    }

    /* the parent process doesn't need the client file descriptor */
    close(fd);

    /* TODO update name to mark it as a server timer? */
    add_test_watchdog(ev_hdl, pid, test->max_duration + TEST_SERVER_EXTRA_TIME,
            test->name);
}



/*
 * A connection has been made on our control port. Accept it and set up an
 * event for when data arrives on this connection.
 */
void control_establish_callback(wand_event_handler_t *ev_hdl, int eventfd,
        __attribute__((unused))void *data,
        __attribute__((unused))enum wand_eventtype_t ev) {

    int fd;
    struct sockaddr_storage remote;
    socklen_t size = sizeof(remote);

    Log(LOG_DEBUG, "Got new control connection");

    if ( (fd = accept(eventfd, (struct sockaddr *)&remote, &size)) < 0 ) {
        Log(LOG_WARNING, "Failed to accept connection on control socket: %s",
                strerror(errno));
        return;
    }

    wand_add_fd(ev_hdl, fd, EV_READ, NULL, control_read_callback);

    return;
}
