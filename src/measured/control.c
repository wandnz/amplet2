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
 * Create the control socket and start it listening for connections.
 */
int initialise_control_socket(char *address, char *port) {
    int sock;
    struct addrinfo hints, *addr, *p;
    int res;
    int one = 1;
    char addrstr[INET6_ADDRSTRLEN];
    void *addrptr = NULL;

    Log(LOG_DEBUG, "Creating control socket");

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ( address == NULL ) {
        hints.ai_family = AF_INET6;
        hints.ai_flags = AI_PASSIVE;
        Log(LOG_DEBUG, "Creating control socket on wildcard:%s", port);
    } else {
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_NUMERICHOST;
        Log(LOG_DEBUG, "Creating control socket on %s:%s", address, port);
    }

    if ( (res = getaddrinfo(address, port, &hints, &addr)) < 0 ) {
        Log(LOG_WARNING, "Failed getaddrinfo(): %s\n", gai_strerror(res));
        return -1;
    }

    /* try all the results from getaddrinfo to find something we can bind to */
    for ( p = addr; p != NULL; p = p->ai_next ) {
        if ( (sock = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) < 0 ) {
            continue;
        }

        if ( setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(int)) < 0 ) {
            close(sock);
            continue;
        }

        if ( bind(sock, p->ai_addr, p->ai_addrlen) < 0 ) {
            close(sock);
            continue;
        }

        break;
    }

    if ( p == NULL ) {
        Log(LOG_WARNING, "Failed to bind control socket, skipping");
        return -1;
    }

    if ( listen(sock, 16) < 0 ) {
        Log(LOG_WARNING, "Failed to listen on control socket: %s",
                strerror(errno));
        return -1;
    }

    switch ( p->ai_family ) {
        case AF_INET: addrptr = &((struct sockaddr_in*)p->ai_addr)->sin_addr;
                      break;
        case AF_INET6: addrptr = &((struct sockaddr_in6*)p->ai_addr)->sin6_addr;
                       break;
    };

    inet_ntop(p->ai_family, addrptr, addrstr, INET6_ADDRSTRLEN);
    Log(LOG_INFO, "Control socket listening on %s:%s", addrstr, port);

    freeaddrinfo(addr);
    return sock;
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

    /* Validate that the client hostname matches the common name in the cert */
    if ( matches_common_name(hostname, client_cert) != 0 ) {
        X509_free(client_cert);
        ssl_shutdown(ssl);
        close(fd);
        exit(0);
    }

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
static void control_read_callback(struct wand_fdcb_t *handle,
        __attribute__((unused))enum wand_eventtype_t ev) {

    wand_event_handler_t *ev_hdl;
    uint8_t test_id;
    test_t *test;
    pid_t pid;
    int fd;

    /*
     * The main event loop shouldn't trigger on these events any more, once
     * we read data from here it is someone elses problem.
     */
    fd = handle->fd;
    ev_hdl = handle->data;
    wand_del_event(ev_hdl, handle);
    free(handle);

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
void control_establish_callback(struct wand_fdcb_t *handle,
        __attribute__((unused))enum wand_eventtype_t ev) {
    int fd;
    struct sockaddr_storage remote;
    socklen_t size = sizeof(remote);
    struct wand_fdcb_t *control_ev = (struct wand_fdcb_t*)malloc(
            sizeof(struct wand_fdcb_t));

    Log(LOG_DEBUG, "Got new control connection");

    if ( (fd = accept(handle->fd, (struct sockaddr *)&remote, &size)) < 0 ) {
        Log(LOG_WARNING, "Failed to accept connection on control socket: %s",
                strerror(errno));
    }

    control_ev->fd = fd;
    control_ev->flags = EV_READ;
    control_ev->data = handle->data;
    control_ev->callback = control_read_callback;
    wand_add_event(handle->data, control_ev);

    return;
}
