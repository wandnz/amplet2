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

#include "global.h"
#include "debug.h"
#include "control.h"
#include "watchdog.h"
#include "modules.h"
#include "testlib.h"
#include "ssl.h"
#include "measured.pb-c.h"
#include "serverlib.h"
#include "schedule.h"
#include "test.h"



/*
 * XXX these names are all very confusing when compared to the protobuf
 * names in common/servers.proto and the associated functions!
 */
static int parse_server_start(void *data, uint32_t len, test_type_t *type) {

    Amplet2__Measured__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__measured__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__MEASURED__CONTROL__TYPE__SERVER ) {
        Log(LOG_WARNING, "Not a SERVER packet, aborting");
        amplet2__measured__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->server || !msg->server->has_test_type ) {
        Log(LOG_WARNING, "Malformed SERVER packet, aborting");
        amplet2__measured__control__free_unpacked(msg, NULL);
        return -1;
    }

    *type = msg->server->test_type;

    /* TODO argv */

    amplet2__measured__control__free_unpacked(msg, NULL);

    return 0;
}



static int parse_schedule_test(void *data, uint32_t len,
        test_schedule_item_t *item) {

    Amplet2__Measured__Control *msg;

    assert(data);
    assert(item);

    /* unpack all the data */
    msg = amplet2__measured__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__MEASURED__CONTROL__TYPE__SCHEDULE ) {
        Log(LOG_WARNING, "Not a SCHEDULE packet, aborting");
        amplet2__measured__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->schedule || !msg->schedule->has_test_type ) {
        Log(LOG_WARNING, "Malformed SCHEDULE packet, aborting");
        amplet2__measured__control__free_unpacked(msg, NULL);
        return -1;
    }

    /* parse schedule message into a schedule item we can run */
    memset(item, 0, sizeof(*item));
    item->test_id = msg->schedule->test_type;
    item->params = parse_param_string(msg->schedule->params);
    //XXX do some hax, can we get a proper one of these from somewhere?
    item->meta = calloc(1, sizeof(amp_test_meta_t));
    item->meta->nssock = "/tmp/foo/var/run/amplet2/jessie-amplet.cms.waikato.ac.nz.sock";

    printf("manually starting %s test\n", amp_tests[item->test_id]->name);

    if ( msg->schedule->n_targets > 0 ) {
        char **targets = calloc(msg->schedule->n_targets + 1, sizeof(char*));
        /* we expect the destinations list to be null terminated */
        memcpy(targets, msg->schedule->targets,
                msg->schedule->n_targets * sizeof(char*));
        targets = populate_target_lists(item, targets);
        if ( targets != NULL && *targets != NULL ) {
            Log(LOG_WARNING, "Too many targets for manual test, ignoring some");
        }
    }

    amplet2__measured__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 *
 */
static void do_start_server(SSL *ssl, void *data, uint32_t len) {
    test_type_t test_type;
    test_t *test;

    /* TODO read test arguments if required */
    if ( parse_server_start(data, len, &test_type) < 0 ) {
        Log(LOG_WARNING, "Failed to parse SERVER packet");
        return;
    }

    Log(LOG_DEBUG, "Read test id %d from control connection", test_type);

    /* Make sure it is a valid test id we are being asked to start */
    if ( test_type >= AMP_TEST_LAST || test_type <= AMP_TEST_INVALID ) {
        Log(LOG_DEBUG, "Read invalid test id on control socket: %d", test_type);
        return;
    }

    /* TODO limit number of connections/servers running, weighted system */

    /* Make sure that the test has been built and loaded */
    if ( (test = amp_tests[test_type]) == NULL ) {
        Log(LOG_DEBUG, "No test module for test id: %d", test_type);
        return;
    }

    /* Make sure that the test requires a server to be run */
    if ( test->server_callback == NULL ) {
        Log(LOG_DEBUG, "No server callback for %s test", test->name);
        return;
    }

    /*
     * Run server function using callback in test, give it the ssl descriptor
     * so that it can report the port number.
     */
    test->server_callback(0, NULL, ssl);
}



static void do_schedule_test(SSL *ssl, void *data, uint32_t len) {
    test_schedule_item_t item;

    Log(LOG_DEBUG, "Got SCHEDULE message");

    if ( parse_schedule_test(data, len, &item) < 0 ) {
        Log(LOG_WARNING, "Failed to parse SCHEDULE packet");
        return;
    }

    Log(LOG_DEBUG, "Manually starting %s test", amp_tests[item.test_id]->name);
    run_test(&item, ssl);
}



/*
 *
 */
static void process_control_message(int fd) {
    SSL *ssl;
    X509 *client_cert;
    int bytes;
    void *data;

    Log(LOG_DEBUG, "Processing control message");

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

    X509_free(client_cert);

    Log(LOG_DEBUG, "Successfully validated peer cert");

    while ( (bytes=read_control_packet_ssl(ssl, &data)) > 0 ) {
        Amplet2__Measured__Control *msg;
        msg = amplet2__measured__control__unpack(NULL, bytes, data);

        switch ( msg->type ) {
            case AMPLET2__MEASURED__CONTROL__TYPE__SERVER: {
                do_start_server(ssl, data, bytes);
                break;
            }

            case AMPLET2__MEASURED__CONTROL__TYPE__SCHEDULE: {
                do_schedule_test(ssl, data, bytes);
                break;
            }

            default: Log(LOG_WARNING, "Unhandled measured control message %d",
                             msg->type);
                     break;
        };

        /* both read_control_packet and unpacking the buffer allocate memory */
        amplet2__measured__control__free_unpacked(msg, NULL);
        free(data);
    }

    ssl_shutdown(ssl);
    close(fd);
    exit(0);
}



/*
 * Short callback to fork a new process for dealing with the control message.
 */
static void control_read_callback(wand_event_handler_t *ev_hdl, int fd,
        __attribute__((unused))void *data,
        __attribute__((unused))enum wand_eventtype_t ev) {

    pid_t pid;

    /*
     * The main event loop shouldn't trigger on these events any more, once
     * we read data from here it is someone elses problem.
     */
    wand_del_fd(ev_hdl, fd);

    /* Fork to validate SSL cert and actually run the server */
    if ( (pid = fork()) < 0 ) {
        Log(LOG_WARNING, "Failed to fork for control connection: %s",
                strerror(errno));
        return;
    } else if ( pid == 0 ) {
        /* TODO need to close up a bunch of file descriptors? dns/asn etc? */
        //close(vars.asnsock_fd);
        //close(vars.nssock_fd);
        reseed_openssl_rng();
        process_control_message(fd);
        assert(0);
    }

    /* the parent process doesn't need the client file descriptor */
    close(fd);

    /*
     * TODO can't start a watchdog now, as the control message could be doing
     * something other than starting a test server. The test server process
     * can't really add this, can anyone, do we care anymore?
     */
    /*
     * TODO when this child terminates, it tries to find a watchdog timer with
     * this pid to kill, but it now doesn't exist. Is this a problem?
     */
#if 0
    add_test_watchdog(ev_hdl, pid, test->max_duration + TEST_SERVER_EXTRA_TIME,
            test->sigint, test->name);
#endif
    //add_test_watchdog(ev_hdl, pid, TEST_SERVER_MAXIMUM_TIME, 0, "server");
}



/*
 * A connection has been made on our control port. Accept it and set up an
 * event for when data arrives on this connection.
 */
static void control_establish_callback(wand_event_handler_t *ev_hdl,
        int eventfd, __attribute__((unused))void *data,
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



/*
 * Create the control socket and start it listening for connections. We
 * use separate sockets for IPv4 and IPv6 so that we can have each of them
 * listening on specific, different addresses.
 */
int initialise_control_socket(wand_event_handler_t *ev_hdl,
        amp_control_t *control) {

    struct addrinfo *addr4, *addr6;
    int one = 1;
    char addrstr[INET6_ADDRSTRLEN];
    struct socket_t sockets;

    Log(LOG_DEBUG, "Creating control socket");

    if ( control == NULL ) {
        Log(LOG_WARNING, "No control socket configuration");
        return -1;
    }

    sockets.socket = -1;
    sockets.socket6 = -1;

    if ( (sockets.socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        Log(LOG_WARNING, "Failed to open IPv4 control socket: %s",
                strerror(errno));
    }
    if ( (sockets.socket6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        Log(LOG_WARNING, "Failed to open IPv6 control socket: %s",
                strerror(errno));
    }

    /* make sure that at least one of them was opened ok */
    if ( sockets.socket < 0 && sockets.socket6 < 0 ) {
        return -1;
    }

    /* set socket options */
    if ( sockets.socket > 0 ) {
        if ( setsockopt(sockets.socket, SOL_SOCKET, SO_REUSEADDR, &one,
                    sizeof(int)) < 0 ) {
            close(sockets.socket);
            sockets.socket = -1;
        }
    }

    if ( sockets.socket6 > 0 ) {
        /* IPV6_V6ONLY prevents it trying to listen on IPv4 as well */
        if ( setsockopt(sockets.socket6, IPPROTO_IPV6, IPV6_V6ONLY, &one,
                    sizeof(one)) < 0 ) {
            close(sockets.socket6);
            sockets.socket6 = -1;
        } else {
            if ( setsockopt(sockets.socket6, SOL_SOCKET, SO_REUSEADDR, &one,
                        sizeof(int)) < 0 ) {
                close(sockets.socket6);
                sockets.socket6 = -1;
            }
        }
    }

    /* bind them to interfaces and addresses if required */
    if ( control->interface &&
            bind_sockets_to_device(&sockets, control->interface) < 0 ) {
        Log(LOG_ERR, "Unable to bind control socket to device, disabling");
        return -1;
    }

    addr4 = get_numeric_address(control->ipv4, control->port);
    addr6 = get_numeric_address(control->ipv6, control->port);

    if ( bind_sockets_to_address(&sockets, addr4, addr6) < 0 ) {
        Log(LOG_ERR,"Unable to bind control socket to address, disabling");
        freeaddrinfo(addr4);
        freeaddrinfo(addr6);
        return -1;
    }

    /* Start listening for control connections on the active sockets */
    if ( sockets.socket > 0 ) {
        if ( listen(sockets.socket, 16) < 0 ) {
            Log(LOG_WARNING, "Failed to listen on IPv4 control socket: %s",
                    strerror(errno));
            close(sockets.socket);
            sockets.socket = -1;
        } else {
            Log(LOG_INFO, "Control socket listening on %s:%s",
                    amp_inet_ntop(addr4, addrstr), control->port);
        }
    }

    if ( sockets.socket6 > 0 ) {
        if ( listen(sockets.socket6, 16) < 0 ) {
            Log(LOG_WARNING, "Failed to listen on IPv6 control socket: %s",
                    strerror(errno));
            close(sockets.socket6);
            sockets.socket6 = -1;
        } else {
            Log(LOG_INFO, "Control socket listening on %s:%s",
                    amp_inet_ntop(addr6, addrstr), control->port);
        }
    }

    freeaddrinfo(addr4);
    freeaddrinfo(addr6);

    /* make sure that at least one of them is listening ok */
    if ( sockets.socket < 0 && sockets.socket6 < 0 ) {
        return -1;
    }

    /* if we have an ipv4 socket then set up the event listener */
    if ( sockets.socket > 0 ) {
        wand_add_fd(ev_hdl, sockets.socket, EV_READ, NULL,
                control_establish_callback);
    }

    /* if we have an ipv6 socket then set up the event listener */
    if ( sockets.socket6 > 0 ) {
        wand_add_fd(ev_hdl, sockets.socket6, EV_READ, NULL,
                control_establish_callback);
    }

    return 0;
}



/*
 *
 */
void free_control_config(amp_control_t *control) {
    if ( control == NULL ) {
        return;
    }

    if ( control->interface ) free(control->interface);
    if ( control->ipv4 ) free(control->ipv4);
    if ( control->ipv6 ) free(control->ipv6);
    if ( control->port ) free(control->port);
    free(control);
}
