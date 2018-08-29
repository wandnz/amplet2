/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
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
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

#include "global.h"
#include "debug.h"
#include "control.h"
#include "watchdog.h"
#include "modules.h"
#include "serverlib.h"
#include "ssl.h"
#include "measured.pb-c.h"
#include "controlmsg.h"
#include "schedule.h"
#include "run.h"
#include "acl.h"



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



/*
 * Extract the parameters for a single-run test from a control message and
 * create a schedule struct for it so it can be run as if it was a normally
 * triggered test.
 */
static int parse_single_test(void *data, uint32_t len,
        test_schedule_item_t *item) {

    Amplet2__Measured__Control *msg;

    assert(data);
    assert(item);

    /* unpack all the data */
    msg = amplet2__measured__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__MEASURED__CONTROL__TYPE__TEST ) {
        Log(LOG_WARNING, "Not a TEST packet, aborting");
        amplet2__measured__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->test || !msg->test->has_test_type ) {
        Log(LOG_WARNING, "Malformed TEST packet, aborting");
        amplet2__measured__control__free_unpacked(msg, NULL);
        return -1;
    }

    /* parse schedule message into a schedule item we can run */
    memset(item, 0, sizeof(*item));
    item->test_id = msg->test->test_type;
    item->params = parse_param_string(msg->test->params);
    item->meta = calloc(1, sizeof(amp_test_meta_t));
    item->meta->inter_packet_delay = MIN_INTER_PACKET_DELAY;
    /*
     * TODO populate these fields based on this amplets default values:
     *   meta->interface
     *   meta->sourcev4
     *   meta->sourcev6
     *   meta->inter_packet_delay
     */

    if ( msg->test->n_targets > 0 ) {
        char **targets = calloc(msg->test->n_targets + 1, sizeof(char*));
        /* we expect the destinations list to be null terminated */
        memcpy(targets, msg->test->targets,
                msg->test->n_targets * sizeof(char*));
        targets = populate_target_lists(item, targets);
        if ( targets != NULL && *targets != NULL ) {
            Log(LOG_WARNING, "Too many targets for manual test, ignoring some");
        }
    }

    amplet2__measured__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 * Validate a server start message and start the appropriate test server if
 * it is successful.
 */
static void do_start_server(BIO *ctrl, void *data, uint32_t len) {
    timer_t watchdog;
    test_type_t test_type;
    test_t *test;
    char *proc_name;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    char opt[IFNAMSIZ];
    socklen_t optlen;
    char *argv[MAX_TEST_ARGS];
    char addrstr[INET6_ADDRSTRLEN];
    int argc;
    int fd;

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

    /* Start the timer so the test will be killed if it runs too long */
    if ( start_test_watchdog(test, &watchdog) < 0 ) {
        Log(LOG_WARNING, "Not starting server for %s test", test->name);
        return;
    }

    /* rename the process so we can tell it is a test server */
    if ( asprintf(&proc_name, "%s server", test->name) < 0 ) {
        Log(LOG_WARNING, "Failed to build process name string");
        return;
    }

    set_proc_name(proc_name);

    argc = 0;
    argv[argc++] = test->name;

    /* get the underlying fd so we can query how it is bound */
    if ( (fd = BIO_get_fd(ctrl, NULL)) < 0 ) {
        Log(LOG_WARNING, "Failed to get underlying file descriptor");
        return;
    }

    /* bind to the same device as the connected control socket */
    optlen = sizeof(opt);
    /* linux >= 3.8 required to get SO_BINDTODEVICE */
    if ( getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &opt, &optlen) == 0 ) {
        /* optlen will be zero if the socket isn't bound to a device */
        if ( optlen > 0 ) {
            argv[argc++] = "-I";
            argv[argc++] = opt;
        }
    }

    /* bind to the same address as the connected control socket */
    addrlen = sizeof(struct sockaddr_storage);
    if ( getsockname(fd, (struct sockaddr*)&addr, &addrlen) == 0 ) {
        void *addrptr;

        switch ( addr.ss_family ) {
            case AF_INET: argv[argc++] = "-4";
                          addrptr = &((struct sockaddr_in*)&addr)->sin_addr;
                          break;
            case AF_INET6: argv[argc++] = "-6";
                           addrptr = &((struct sockaddr_in6*)&addr)->sin6_addr;
                           break;
            default: addrptr = NULL; break;
        };

        if ( addrptr ) {
            inet_ntop(addr.ss_family, addrptr, addrstr, INET6_ADDRSTRLEN);
            argv[argc++] = addrstr;
        }
    }

    argv[argc] = NULL;

    /* Run server function using callback in test */
    test->server_callback(argc, argv, ctrl);

    stop_watchdog(watchdog);

    free_duped_environ();
    free(proc_name);
}



/*
 * Validate a single-run test message and run the appropriate test if it is
 * successful.
 */
static void do_single_test(BIO *ctrl, void *data, uint32_t len) {
    test_schedule_item_t item;

    Log(LOG_DEBUG, "Got TEST message");

    if ( parse_single_test(data, len, &item) < 0 ) {
        Log(LOG_WARNING, "Failed to parse TEST packet");
        return;
    }

    Log(LOG_DEBUG, "Manually starting %s test", amp_tests[item.test_id]->name);

    run_test(&item, ctrl);
}



/*
 * Establish an SSL connection and read control messages from it, acting on
 * each message.
 */
static void process_control_message(int fd, struct acl_root *acl) {
    BIO *ctrl;
    SSL *ssl;
    X509 *client_cert;
    char *common_name;
    int bytes;
    void *data;

    Log(LOG_DEBUG, "Processing control message");

    assert(ssl_ctx);

    /* Open up the ssl channel and validate the cert against our CA cert */
    /* TODO CRL or OCSP to deal with revocation of certificates */
    if ( (ctrl = establish_control_socket(ssl_ctx, fd, 0)) == NULL ) {
        close(fd);
        exit(EXIT_FAILURE);
    }

    /* We expect to be using SSL here, can't get the common name otherwise! */
    BIO_get_ssl(ctrl, &ssl);
    if ( ssl == NULL ) {
        Log(LOG_WARNING, "Failed to get SSL pointer from BIO");
        close_control_connection(ctrl);
        exit(EXIT_FAILURE);
    }

    /* Get the peer certificate so we can check the common name */
    client_cert = SSL_get_peer_certificate(ssl);
    if ( client_cert == NULL ) {
        Log(LOG_WARNING, "Failed to get peer certificate");
        close_control_connection(ctrl);
        exit(EXIT_FAILURE);
    }

    /* Get the common name, we'll use this with the ACL shortly */
    if ( (common_name = get_common_name(client_cert)) == NULL ) {
        Log(LOG_WARNING, "No common name, aborting");
        close_control_connection(ctrl);
        exit(EXIT_FAILURE);
    }

    //Log(LOG_DEBUG, "Successfully validated peer cert");

    while ( (bytes = read_control_packet(ctrl, &data)) > 0 ) {
        Amplet2__Measured__Control *msg;
        msg = amplet2__measured__control__unpack(NULL, bytes, data);

        /* make sure the message was valid and unpacked properly */
        if ( !msg || !msg->has_type ) {
            break;
        }

        switch ( msg->type ) {
            case AMPLET2__MEASURED__CONTROL__TYPE__SERVER: {
                if ( get_acl(acl, common_name, ACL_SERVER) ) {
                    //TODO move this after we know server started ok?
                    send_measured_response(ctrl, MEASURED_CONTROL_OK, "OK");
                    do_start_server(ctrl, data, bytes);
                } else {
                    Log(LOG_WARNING, "Host %s lacks ACL_SERVER permissions",
                            common_name);
                    send_measured_response(ctrl, MEASURED_CONTROL_FORBIDDEN,
                        "Requires SERVER permissions");
                }
                break;
            }

            case AMPLET2__MEASURED__CONTROL__TYPE__TEST: {
                if ( get_acl(acl, common_name, ACL_TEST) ) {
                    //TODO move this after we know test was parsed ok?
                    send_measured_response(ctrl, MEASURED_CONTROL_OK, "OK");
                    do_single_test(ctrl, data, bytes);
                } else {
                    Log(LOG_WARNING, "Host %s lacks ACL_TEST permissions",
                            common_name);
                    send_measured_response(ctrl, MEASURED_CONTROL_FORBIDDEN,
                        "Requires TEST permissions");
                }
                break;
            }

            default: Log(LOG_WARNING, "Unhandled measured control message %d",
                             msg->type);
                     send_measured_response(ctrl, MEASURED_CONTROL_BADREQUEST,
                             "Bad request");
                     break;
        };

        /* both read_control_packet and unpacking the buffer allocate memory */
        amplet2__measured__control__free_unpacked(msg, NULL);
        free(data);
    }

    close_control_connection(ctrl);
    X509_free(client_cert);

    exit(EXIT_SUCCESS);
}



/*
 * Short callback to fork a new process for dealing with the control message.
 * TODO this is very very similar to test.c:fork_test()
 */
static void control_read_callback(wand_event_handler_t *ev_hdl, int fd,
        void *data, __attribute__((unused))enum wand_eventtype_t ev) {

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
        /*
         * close the unix domain sockets the parent had, if we keep them open
         * then things can get confusing (test threads end up holding the
         * socket open when it should be closed).
         */
        close(vars.asnsock_fd);
        close(vars.nssock_fd);

        /* unblock signals and remove handlers that the parent process added */
        if ( unblock_signals() < 0 ) {
            Log(LOG_WARNING, "Failed to unblock signals, aborting");
            exit(EXIT_FAILURE);
        }

        reseed_openssl_rng();
        process_control_message(fd, (struct acl_root*)data);
        exit(EXIT_SUCCESS);
    }

    /* the parent process doesn't need the client file descriptor */
    close(fd);
}



/*
 * A connection has been made on our control port. Accept it and set up an
 * event for when data arrives on this connection.
 */
static void control_establish_callback(wand_event_handler_t *ev_hdl,
        int eventfd, void *data,
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

    wand_add_fd(ev_hdl, fd, EV_READ, data, control_read_callback);

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
    addr4 = NULL;
    addr6 = NULL;

    /* only set up the ipv4 socket if we have an address to listen on */
    if ( control->ipv4 ) {
        addr4 = get_numeric_address(control->ipv4, control->port);
        if ( (sockets.socket=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) > 0 ) {
            if ( setsockopt(sockets.socket, SOL_SOCKET, SO_REUSEADDR, &one,
                        sizeof(int)) < 0 ) {
                close(sockets.socket);
                sockets.socket = -1;
            }
        } else {
            Log(LOG_WARNING, "Failed to open IPv4 control socket: %s",
                    strerror(errno));
        }
    }

    /* only set up the ipv6 socket if we have an address to listen on */
    if ( control->ipv6 ) {
        addr6 = get_numeric_address(control->ipv6, control->port);
        if ( (sockets.socket6=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) > 0 ){
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
        } else {
            Log(LOG_WARNING, "Failed to open IPv6 control socket: %s",
                    strerror(errno));
        }
    }

    /* make sure that at least one of them was opened ok */
    if ( sockets.socket < 0 && sockets.socket6 < 0 ) {
        if ( addr4 ) {
            freeaddrinfo(addr4);
        }

        if ( addr6 ) {
            freeaddrinfo(addr6);
        }
        return -1;
    }

    /* bind them to interfaces and addresses if required */
    if ( control->interface &&
            bind_sockets_to_device(&sockets, control->interface) < 0 ) {
        Log(LOG_ERR, "Unable to bind control socket to device, disabling");
        if ( addr4 ) {
            freeaddrinfo(addr4);
        }

        if ( addr6 ) {
            freeaddrinfo(addr6);
        }
        return -1;
    }

    if ( bind_sockets_to_address(&sockets, addr4, addr6) < 0 ) {
        Log(LOG_ERR,"Unable to bind control socket to address, disabling");
        if ( addr4 ) {
            freeaddrinfo(addr4);
        }

        if ( addr6 ) {
            freeaddrinfo(addr6);
        }
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

    if ( addr4 ) {
        freeaddrinfo(addr4);
    }

    if ( addr6 ) {
        freeaddrinfo(addr6);
    }

    /* make sure that at least one of them is listening ok */
    if ( sockets.socket < 0 && sockets.socket6 < 0 ) {
        return -1;
    }

    /* if we have an ipv4 socket then set up the event listener */
    if ( sockets.socket > 0 ) {
        wand_add_fd(ev_hdl, sockets.socket, EV_READ, control->acl,
                control_establish_callback);
    }

    /* if we have an ipv6 socket then set up the event listener */
    if ( sockets.socket6 > 0 ) {
        wand_add_fd(ev_hdl, sockets.socket6, EV_READ, control->acl,
                control_establish_callback);
    }

    return 0;
}



/*
 * Free all the memory associated with control port interfaces/devices/acl.
 */
void free_control_config(amp_control_t *control) {
    if ( control == NULL ) {
        return;
    }

    if ( control->interface ) free(control->interface);
    if ( control->ipv4 ) free(control->ipv4);
    if ( control->ipv6 ) free(control->ipv6);
    if ( control->port ) free(control->port);
    if ( control->acl ) free_acl(control->acl);
    free(control);
}
