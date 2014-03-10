#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <amqp.h>
#include <amqp_framing.h>

#include "testlib.h"
#include "debug.h"
#include "tests.h"
#include "modules.h"
#include "messaging.h"
#include "ssl.h"
#include "global.h"



/*
 * Given a pair of sockets (ipv4 and ipv6), wait for data to arrive on either
 * of them, up to maxwait microseconds. If data arrives before the timeout
 * then return which socket received the data, otherwise -1.
 */
int wait_for_data(struct socket_t *sockets, int *maxwait) {
    struct timeval start_time, end_time;
    struct timeval timeout;
    int delay;
    int max_fd;
    int ready;
    fd_set readset;

    assert(sockets);
    assert(sockets->socket || sockets->socket6);

    gettimeofday(&start_time, NULL);

    max_fd = -1;
    delay = 0;

    do {
	/*
	 * if there has been an error then update timeout by how long we have
	 * already taken so we can carry on where we left off
	 */
	if ( delay > *maxwait ) {
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 0;
	} else {
	    timeout.tv_sec = S_FROM_US(*maxwait - delay);
	    timeout.tv_usec = US_FROM_US(*maxwait - delay);
	}

	/* fd sets are undefined after an error, so set them every time too */
	FD_ZERO(&readset);
	if ( sockets->socket > 0 ) {
	    FD_SET(sockets->socket, &readset);
	    max_fd = sockets->socket;
	}

	if ( sockets->socket6 > 0 ) {
	    FD_SET(sockets->socket6, &readset);
	    if ( sockets->socket6 > max_fd ) {
		max_fd = sockets->socket6;
	    }
	}

	ready = select(max_fd+1, &readset, NULL, NULL, &timeout);

	/*
	 * we can't always trust the value of timeout after select returns, so
	 * check for ourselves how much time has elapsed
	 */
	gettimeofday(&end_time, NULL);
	delay = DIFF_TV_US(end_time, start_time);

	/* if delay is less than zero then maybe the clock was adjusted */
	if ( delay < 0 ) {
	    delay = 0;
	}

	/* continue until there is data to read or we get a non EINTR error */
    } while ( ready < 0 && errno == EINTR );

    /* remove the time waited so far from maxwait */
    *maxwait -= delay;
    if ( *maxwait < 0 ) {
	*maxwait = 0;
    }

    /* if there was a non-EINTR error then report it */
    if ( ready < 0 ) {
	Log(LOG_WARNING, "select() failed");
	return -1;
    }

    /* return the appropriate socket that has data waiting */
    if ( sockets->socket > 0 && FD_ISSET(sockets->socket, &readset) ) {
	return AF_INET;
    }

    if ( sockets->socket6 > 0 && FD_ISSET(sockets->socket6, &readset) ) {
	return AF_INET6;
    }

    return -1;
}



/*
 * Wait for up to timeout microseconds to receive a packet on the given
 * sockets and return the number of bytes read.
 */
int get_packet(struct socket_t *sockets, char *buf, int len,
        struct sockaddr *saddr, int *timeout) {

    int bytes;
    int sock;
    int family;
    socklen_t addrlen;

    assert(sockets);
    assert(sockets->socket || sockets->socket6);

    /* wait for data to be ready, up to timeout (wait will update it) */
    if ( (family = wait_for_data(sockets, timeout)) <= 0 ) {
        return 0;
    }

    /* determine which socket we have received data on and read from it */
    switch ( family ) {
        case AF_INET: sock = sockets->socket;
                      addrlen = sizeof(struct sockaddr_in);
                      break;
        case AF_INET6: sock = sockets->socket6;
                       addrlen = sizeof(struct sockaddr_in6);
                       break;
        default: return 0;
    };

    if ( (bytes = recvfrom(sock, buf, len, 0, saddr, &addrlen)) < 0 ) {
        Log(LOG_ERR, "Failed to recvfrom()");
        exit(-1);
    }

    return bytes;
}



/*
 * Enforce a minimum inter-packet delay for test traffic. Try to send a packet
 * but if it is too soon for the test to be sending again then return a delay
 * time to wait (in microseconds).
 */
int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest) {

    int bytes_sent;
    static struct timeval last = {0, 0};
    struct timeval now;
    int delay;

    assert(sock > 0);
    assert(size > 0);
    assert(packet);
    assert(dest);

    gettimeofday(&now, NULL);

    /* determine how much time is left to wait until the minimum delay */
    if ( last.tv_sec != 0 && DIFF_TV_US(now, last) < MIN_INTER_PACKET_DELAY ) {
	delay = MIN_INTER_PACKET_DELAY - DIFF_TV_US(now, last);
    } else {
	delay = 0;
	last.tv_sec = now.tv_sec;
	last.tv_usec = now.tv_usec;
    }

    /*
     * if there is still time to wait before the next packet then return
     * control to the caller, in case they want to do more work while waiting
     */
    if ( delay != 0 ) {
	return delay;
    }

    bytes_sent = sendto(sock, packet, size, 0, dest->ai_addr, dest->ai_addrlen);

    /* TODO determine error and/or send any unsent bytes */
    if ( bytes_sent != size ) {
        Log(LOG_DEBUG, "Only sent %d of %d bytes", bytes_sent, size);
        return -1;
    }

    return 0;
}



/*
 * If the test is set to report (i.e. being run through measured) then
 * send the data buffer to the local broker for transmission to the
 * server. Otherwise if the test is being run standalone then use the
 * test specific printing functions to dump a human readable version of
 * the data to stdout.
 */
int report(test_type_t type, uint64_t timestamp, void *bytes, size_t len) {
    if ( type >= AMP_TEST_LAST || type <= AMP_TEST_INVALID ) {
	Log(LOG_WARNING, "Test type %d out of range, not reporting\n", type);
	return -1;
    }

    if ( amp_tests[type] == NULL ) {
	Log(LOG_WARNING, "Invalid test type %d, not reporting\n", type);
	return -1;
    }

    if ( amp_tests[type]->report ) {
	report_to_broker(type, timestamp, bytes, len);
    } else {
	/* the generic test main function should make sure this is set */
	amp_tests[type]->print_callback(bytes, len);
    }

    return 0;
}



/*
 * Determine the name for a given address structure. Currently the name is
 * stored using the ai_canonname field in the struct addrinfo, which is
 * filled in when the structure is created (but not by getaddrinfo).
 */
char *address_to_name(struct addrinfo *address) {
    assert(address);
    assert(address->ai_canonname);
    return address->ai_canonname;
}



/*
 * Send a port number over an SSL connection. Mostly just a convenience for
 * starting test servers to save having to remember how to send SSL data and
 * byteswap.
 */
int send_server_port(SSL *ssl, uint16_t port) {
    int result = 0;

    assert(ssl);
    assert(ssl_ctx);

    Log(LOG_DEBUG, "Sending server port %d", port);

    port = htons(port);

    if ( SSL_write(ssl, &port, sizeof(port)) != sizeof(port) ) {
        result = -1;
    }

    /* Looks like we have to close this here rather than after the test
     * completes, cause start_remote_server() closes it immediately after
     * getting the port number. Doing it later would probably require shipping
     * the SSL object around and/or relying on the test itself to tidy up.
     */
    ssl_shutdown(ssl);
    return result;
}



/*
 * Open an SSL connection to another AMP monitor and ask them to start a
 * server for a particular test. This will return the port number that the
 * server is running on.
 */
uint16_t start_remote_server(test_type_t type, struct addrinfo *dest) {
    SSL *ssl;
    X509 *server_cert;
    int sock;
    uint16_t bytes, server_port, control_port;
    int res;
    int attempts;

    assert(dest);
    assert(dest->ai_addr);
    assert(vars.control_port);

    if ( ssl_ctx == NULL ) {
        Log(LOG_WARNING, "Can't start remote server, no SSL configuration");
        return 0;
    }

    Log(LOG_DEBUG, "Starting remote server for test type %d", type);

    /* vars.control_port is a char*, cause getaddrinfo needs that elsewhere */
    control_port = atol(vars.control_port);
    switch ( dest->ai_family ) {
        case AF_INET: ((struct sockaddr_in *)dest->ai_addr)->sin_port =
                      htons(control_port);
                      break;
        case AF_INET6: ((struct sockaddr_in6 *)dest->ai_addr)->sin6_port =
                       htons(control_port);
                       break;
        default: return 0;
    };

    /* Open connection to the remote AMP monitor */
    if ( (sock = socket(dest->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        Log(LOG_DEBUG, "Failed to create socket");
        return 0;
    }

    /* Try a few times to connect, but give up after failing too many times */
    attempts = 0;
    do {
        char addrstr[INET6_ADDRSTRLEN];
        if ( (res = connect(sock, dest->ai_addr, dest->ai_addrlen)) < 0 ) {
            attempts++;

            /*
             * The destination is from our nametable, so it should have a
             * useful canonical name set, we aren't relying on getaddrinfo.
             */
            Log(LOG_DEBUG, "Failed to connect to %s (%s) attempt %d/%d: %s",
                    dest->ai_canonname,
                    amp_inet_ntop(dest, addrstr), attempts,
                    MAX_CONNECT_ATTEMPTS, strerror(errno));

            if ( attempts >= MAX_CONNECT_ATTEMPTS ) {
                Log(LOG_WARNING,
                        "Failed too many times connecting to %s (%s), aborting",
                        dest->ai_canonname, amp_inet_ntop(dest, addrstr));
                return 0;
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

    /* Send the test type, so the other end can set up watchdogs etc */
    if ( send(sock, &type, 1, 0) < 0 ) {
        Log(LOG_DEBUG, "Failed to send test type");
        close(sock);
        return 0;
    }

    /* Open up the ssl channel and validate the cert against our CA cert */
    /* TODO CRL or OCSP to deal with revocation of certificates */

    /* Do the SSL handshake */
    if ( (ssl = ssl_connect(ssl_ctx, sock) ) == NULL ) {
        Log(LOG_DEBUG, "Failed to setup SSL connection");
        close(sock);
        return 0;
    }

    /* Recover the server's certificate */
    server_cert = SSL_get_peer_certificate(ssl);
    if ( server_cert == NULL ) {
        Log(LOG_DEBUG, "Failed to get peer certificate");
        close(sock);
        return 0;
    }

    /* Validate the hostname */
    if ( matches_common_name(dest->ai_canonname, server_cert) != 0 ) {
        Log(LOG_DEBUG, "Hostname validation failed");
        X509_free(server_cert);
        ssl_shutdown(ssl);
        close(sock);
        return 0;
    }

    Log(LOG_DEBUG, "Successfully validated peer cert");

    /* TODO send any test parameters? */
    /* Get the port number the remote server is on */
    bytes = 0;
    while ( bytes < sizeof(server_port) ) {
        /* read the message straight into the port variable, 2 bytes long */
        res = SSL_read(ssl, ((char*)&server_port) + bytes, sizeof(server_port));
        if ( res > 0 ) {
            bytes += res;
        }
    }

    /* Response didn't make sense, zero the port so the client knows */
    if ( bytes != sizeof(server_port) ) {
        Log(LOG_WARNING, "Expected %d bytes, got %d bytes, not a valid port",
                sizeof(server_port), bytes);
        server_port = 0;
    }

    server_port = ntohs(server_port);

    Log(LOG_DEBUG, "Remote port number: %d", server_port);

    X509_free(server_cert);
    ssl_shutdown(ssl);
    close(sock);

    return server_port;
}



/*
 *
 */
struct addrinfo *get_numeric_address(char *address) {
    struct addrinfo hints, *result;

    assert(address);

    Log(LOG_DEBUG, "Trying to get numeric host for %s", address);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    /* XXX do we need to set socktype or protocol? */

    /* check if the given string is one of our addresses */
    if ( getaddrinfo(address, NULL, &hints, &result) == 0 ) {
        return result;
    }

    return NULL;
}



/*
 * Bind a socket to a particular network device.
 */
static int bind_socket_to_device(int sock, char *device) {
    assert(device);

    Log(LOG_DEBUG, "Trying to bind socket to device '%s'", device);

    if ( setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device,
                strlen(device)+1) < 0 ) {
        Log(LOG_WARNING, "Failed to bind to device %s", device);
        return -1;
    }

    return 0;
}



/*
 * Bind a socket to a particular address.
 */
static int bind_socket_to_address(int sock, struct addrinfo *address) {
    char addrstr[INET6_ADDRSTRLEN];

    assert(address);
    assert(sock >= 0);

    Log(LOG_DEBUG, "Binding socket to source address %s",
            amp_inet_ntop(address, addrstr));

    if ( bind(sock, ((struct sockaddr*)address->ai_addr),
                address->ai_addrlen) < 0 ) {
        Log(LOG_DEBUG, "Failed to bind socket to address: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Bind all sockets in the test socket structure to a particular device.
 * Will only try to bind valid test sockets - if one of the IPv4 and IPv6
 * sockets isn't set then it will be ignored.
 */
int bind_sockets_to_device(struct socket_t *sockets, char *device) {
    Log(LOG_DEBUG, "Binding ICMP test to interface %s", device);
    assert(sockets);
    assert(sockets->socket >= 0 || sockets->socket6 >= 0);
    assert(device);

    if ( sockets->socket >= 0 ) {
        if ( bind_socket_to_device(sockets->socket, device) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv4 socket to device %s", device);
            return -1;
        }
    }

    if ( sockets->socket6 >= 0 ) {
        if ( bind_socket_to_device(sockets->socket6, device) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv6 socket to device %s", device);
            return -1;
        }
    }

    return 0;
}



/*
 * Bind the sockets in the test socket structure to a particular source
 * address (one for IPv4 and one for IPv6 obviously). Will only try to bind
 * valid test sockets - if one of the IPv4 and IPv6 sockets isn't set or
 * there is no address set for that family then it will be ignored.
 */
int bind_sockets_to_address(struct socket_t *sockets,
        struct addrinfo *sourcev4, struct addrinfo *sourcev6) {
    char addrstr[INET6_ADDRSTRLEN];

    assert(sockets);
    assert( (sockets->socket >= 0 && sourcev4) ||
            (sockets->socket6 >= 0 && sourcev6) );

    if ( sourcev4 && sockets->socket >= 0 ) {
        Log(LOG_DEBUG, "Binding ICMP test to source IPv4 address %s",
                amp_inet_ntop(sourcev4, addrstr));

        if ( bind_socket_to_address(sockets->socket, sourcev4) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv4 socket to address: %s",
                amp_inet_ntop(sourcev4, addrstr));
            return -1;
        }
    }

    if ( sourcev6 && sockets->socket6 >= 0 ) {
        Log(LOG_DEBUG, "Binding ICMP test to source IPv6 address %s",
                amp_inet_ntop(sourcev6, addrstr));

        if ( bind_socket_to_address(sockets->socket6, sourcev6) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv6 socket to address: %s",
                amp_inet_ntop(sourcev6, addrstr));
            return -1;
        }
    }

    return 0;
}
