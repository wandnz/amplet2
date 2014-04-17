#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
/* XXX mempcpy() */
#define _GNU_SOURCE
#include <string.h>

#include <resolv.h>
#include <arpa/inet.h>

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

    /*
     * man SSL_write:
     * SSL_write() will only return with success, when the complete contents
     * of buf of length num has been written.
     */
    if ( SSL_write(ssl, &port, sizeof(port)) <= 0 ) {
        result = -1;
    }

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

    if ( vars.interface ) {
        if ( bind_socket_to_device(sock, vars.interface) < 0 ) {
            return 0;
        }
    }

    if ( vars.sourcev4 || vars.sourcev6 ) {
        struct addrinfo *addr;

        switch ( dest->ai_family ) {
            case AF_INET: addr = get_numeric_address(vars.sourcev4, NULL);
                          break;
            case AF_INET6: addr = get_numeric_address(vars.sourcev6, NULL);
                           break;
            default: return 0;
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
                return 0;
            }
        }
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

        if ( res <= 0 ) {
            break;
        }
        bytes += res;
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
struct addrinfo *get_numeric_address(char *address, char *port) {
    struct addrinfo hints, *result;

    assert(address);

    Log(LOG_DEBUG, "Trying to get numeric host for %s", address);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    /* XXX do we need to set socktype or protocol? */

    /* check if the given string is one of our addresses */
    if ( getaddrinfo(address, port, &hints, &result) == 0 ) {
        return result;
    }

    return NULL;
}



/*
 * Bind a socket to a particular network device.
 */
int bind_socket_to_device(int sock, char *device) {
    assert(device);

    Log(LOG_DEBUG, "Trying to bind socket to device '%s'", device);

    if ( setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device,
                strlen(device)+1) < 0 ) {
        Log(LOG_WARNING, "Failed to bind to device %s: %s", device,
                strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Bind a socket to a particular address.
 */
int bind_socket_to_address(int sock, struct addrinfo *address) {
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
    Log(LOG_DEBUG, "Binding socket to interface %s", device);
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
        Log(LOG_DEBUG, "Binding socket to source IPv4 address %s",
                amp_inet_ntop(sourcev4, addrstr));

        if ( bind_socket_to_address(sockets->socket, sourcev4) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv4 socket to address: %s",
                amp_inet_ntop(sourcev4, addrstr));
            return -1;
        }
    }

    if ( sourcev6 && sockets->socket6 >= 0 ) {
        Log(LOG_DEBUG, "Binding socket to source IPv6 address %s",
                amp_inet_ntop(sourcev6, addrstr));

        if ( bind_socket_to_address(sockets->socket6, sourcev6) < 0 ) {
            Log(LOG_DEBUG, "Failed to bind IPv6 socket to address: %s",
                amp_inet_ntop(sourcev6, addrstr));
            return -1;
        }
    }

    return 0;
}


/*
 * XXX
 * If we set the nameservers, we need to clobber all the nsaddrs and
 * nsaddr_list structures with our own.
 *
 * If we set any interfaces or addresses, we need to clobber the sockets
 * with our own ( this needs nsaddrs and nsaddr_list to be set up right,
 * i.e. everything needs an nsaddrs entry, which v4 doesnt have till after
 * processing).
 */

/*
 * Initialise the extended info block by copying the IPv4 nameservers from
 * _res.nsaddr_list[] into _res._u._ext.nsaddrs[] and setting up the nsmap[]
 * array appropriately. We need to do this ourselves so that it is set up
 * and ready to go when we make our own sockets, otherwise libc will do it
 * all for us and not apply the socket config.
 *
 * Was initially based on the initialisation code from
 * eglibc-2.13/resolv/res_send.c, but is now trimmed down to be just the bits
 * I need and much less generic.
 */
#define EXT(res) ((res)->_u._ext)
void init_default_nameservers(void) {
    res_state statp;
    int i;

    Log(LOG_DEBUG, "Manually init default nameservers\n");

    if ( !(_res.options & RES_INIT) ) {
        res_init();
    }

    statp = &_res;


    for ( i = 0; i < MAXNS; i++ ) {

        /* NULL any empty servers that are past our ones */
        if ( i >= _res.nscount ) {
            _res._u._ext.nsaddrs[i] = NULL;
            continue;
        }

        /* XXX could these already be open and need closing first? */
        _res._u._ext.nssocks[i] = -1;

        /* IPv6 ones are already done right */
        if ( _res._u._ext.nsmap[i] == MAXNS + 1 ) {
            continue;
        }

        /* These are IPv4 ones that haven't been set up yet */
        if ( _res._u._ext.nsmap[i] == MAXNS ) {
            /* update map to point to the right nsaddr_list entry */
            _res._u._ext.nsmap[i] = i;
            /* copy it into the extended nsaddrs[] array */
            if ( _res._u._ext.nsaddrs[i] == NULL ) {
                _res._u._ext.nsaddrs[i] = malloc(sizeof (struct sockaddr_in6));
            }
            memcpy(_res._u._ext.nsaddrs[i], &_res.nsaddr_list[i],
                    sizeof(struct sockaddr_in));
        }
    }

    /* Update address counts */
    _res._u._ext.nscount = _res.nscount;
    if ( _res._u._ext.nscount6 > 0 ) {
        _res.ipv6_unavail = 0;
    }

    /* We still need to do this? Aren't we doing all the work now? */
    _res._u._ext._initstamp[0]++;
}



/*
 * Open a socket for connecting to a nameserver. Copied from
 * eglibc-2.13/resolv/res_send.c with modifications to set source interface
 * and/or addresses. We need to do this because we sometimes want full contol
 * over which interfaces/addresses our traffic uses.
 */
#include <fcntl.h>
#ifndef __ASSUME_SOCK_CLOEXEC
static int __have_o_nonblock;
#else
# define __have_o_nonblock 0
#endif
static int open_nameserver_socket(res_state statp, int ns) {
    if ( EXT(statp).nssocks[ns] == -1 ) {
        struct sockaddr *nsap = (struct sockaddr *) EXT(statp).nsaddrs[ns];
        socklen_t slen;
        /* only try IPv6 if IPv6 NS and if not failed before */
        if (nsap->sa_family == AF_INET6 && !statp->ipv6_unavail) {
            if (__builtin_expect (__have_o_nonblock >= 0, 1)) {
                EXT(statp).nssocks[ns] =
                    socket(PF_INET6, SOCK_DGRAM|SOCK_NONBLOCK, 0);
#ifndef __ASSUME_SOCK_CLOEXEC
                if (__have_o_nonblock == 0) {
                    __have_o_nonblock
                        = (EXT(statp).nssocks[ns] == -1
                                && errno == EINVAL ? -1 : 1);
                }
#endif
            }
            if (__builtin_expect (__have_o_nonblock < 0, 0)) {
                EXT(statp).nssocks[ns] = socket(PF_INET6, SOCK_DGRAM, 0);
            }
            if (EXT(statp).nssocks[ns] < 0) {
                statp->ipv6_unavail = errno == EAFNOSUPPORT;
            }
            slen = sizeof (struct sockaddr_in6);

        } else if (nsap->sa_family == AF_INET) {
            if (__builtin_expect (__have_o_nonblock >= 0, 1)) {
                EXT(statp).nssocks[ns]
                    = socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, 0);
#ifndef __ASSUME_SOCK_CLOEXEC
                if (__have_o_nonblock == 0) {
                    __have_o_nonblock
                        = (EXT(statp).nssocks[ns] == -1
                                && errno == EINVAL ? -1 : 1);
                }
#endif
            }
            if (__builtin_expect (__have_o_nonblock < 0, 0)) {
                EXT(statp).nssocks[ns] = socket(PF_INET, SOCK_DGRAM, 0);
            }
            slen = sizeof (struct sockaddr_in);
        }
        if (EXT(statp).nssocks[ns] < 0) {
            //*terrno = errno;
            //Perror(statp, stderr, "socket(dg)", errno);
            return (-1);
        }


        /*
         * Local modifications to set socket options on the name resolution
         * sockets. If we want to make our traffic use a specific interface
         * or address then we have to set these on every single socket we
         * ever use.
         */
        if ( vars.interface ) {
            if ( bind_socket_to_device(EXT(statp).nssocks[ns],
                        vars.interface) < 0 ) {
                return -1;
            }
        }

        if ( nsap->sa_family == AF_INET && vars.sourcev4 ) {
            struct addrinfo *addr = get_numeric_address(vars.sourcev4, NULL);
            if ( bind_socket_to_address(EXT(statp).nssocks[ns], addr) < 0 ) {
                return -1;
            }

        } else if ( nsap->sa_family == AF_INET6 && vars.sourcev6 ) {
            struct addrinfo *addr = get_numeric_address(vars.sourcev6, NULL);
            if ( bind_socket_to_address(EXT(statp).nssocks[ns], addr) < 0 ) {
                return -1;
            }
        }

        /*
         * On a 4.3BSD+ machine (client and server,
         * actually), sending to a nameserver datagram
         * port with no nameserver will cause an
         * ICMP port unreachable message to be returned.
         * If our datagram socket is "connected" to the
         * server, we get an ECONNREFUSED error on the next
         * socket operation, and select returns if the
         * error message is received.  We can thus detect
         * the absence of a nameserver without timing out.
         */
        if (connect(EXT(statp).nssocks[ns], nsap, slen) < 0) {
            //XXX do we want to do these?
            //Aerror(statp, stderr, "connect(dg)", errno, nsap);
            //__res_iclose(statp, 0);
            return (0);
        }
        if (__builtin_expect (__have_o_nonblock < 0, 0)) {
            /* Make socket non-blocking.  */
            int fl = fcntl (EXT(statp).nssocks[ns], F_GETFL);
            if  (fl != -1) {
                fcntl (EXT(statp).nssocks[ns], F_SETFL, fl | O_NONBLOCK);
            }
        }
    }

    return 1;
}



/*
 * Open our own sockets to use for name resolution, because we want to apply
 * extra options to the sockets that we can't otherwise do. This is useful
 * in the case where we want to use specific source addresses or interfaces,
 * which must be configured on a per-socket basis.
 */
void open_nameserver_sockets(void) {
    int i;

    Log(LOG_DEBUG, "Opening custom sockets for name resolution");

    /* Open sockets for each of the configured nameservers */
    for ( i = 0; i < MAXNS; i++ ) {
        if ( _res._u._ext.nsaddrs[i] != NULL ) {
            open_nameserver_socket(&_res, i);
        }
    }

    /*
     * Don't close our sockets between queries, we don't want libresolv
     * to come along and reopen them differently to how we have them. The
     * docs suggest this is only for TCP, but the source says otherwise.
     */
    _res.options |= RES_STAYOPEN;

    /*
     * Mark everything as already initialised so that it doesn't get looked
     * at later by libc. We have already done all the work and don't want it
     * poking around and messing things up.
     */
    _res._u._ext.nsinit = 1;
}



/*
 * Override some internal libc structures to replace the default resolvers
 * read from /etc/resolv.conf with some of our own. The _res structure stores
 * up to MAXNS (currently 3) nameservers, in some combination of IPv4 and IPv6.
 * IPv4 ones are stored in _res.nsaddr_list[] while IPv6 ones are stored in
 * _res._u._ext.nsaddrs[].
 *
 * There isn't a lot of documentation around this, but I've mostly been
 * working from:
 *      /usr/include/resolv.h
 *      https://sourceware.org/ml/libc-hacker/2002-05/msg00035.html
 *      eglibc-2.13/resolv/res_libc.c
 *      eglibc-2.13/resolv/res_init.c
 *      eglibc-2.13/resolv/res_send.c
 */
int update_nameservers(char *servers[], int count) {
    int i;
    struct sockaddr_storage *ss;
    int nservall = 0;
    int nserv = 0;

    /* Don't do anything if we get obviously bad input */
    if ( count < 1 || servers == NULL ) {
        Log(LOG_WARNING, "No nameservers specified, using defaults");
        return 0;
    }

    Log(LOG_DEBUG, "Replacing default nameservers with %d custom ones", count);

    /* don't stop here, but give us a clue in case weirdness happens */
    if ( count > MAXNS ) {
        Log(LOG_WARNING,
                "Too many nameservers, using only the first %d valid entries",
                MAXNS);
    }

    /* initialise the _res struct, so that we can modify it */
    if ( !(_res.options & RES_INIT) ) {
        res_init();
    }

    /* update the initstamp value so things get reinitialised later */
    //XXX do we need to do this now that i do it manually?
    _res._u._ext._initstamp[0]++;

    /* probably don't need to set all these, they get set at the end */
    _res.nscount = 0;
    _res._u._ext.nscount = 0;
    _res._u._ext.nscount6 = 0;

    /* clear out any existing nameservers */
    memset(&_res.nsaddr_list, 0, sizeof(struct sockaddr_in) * MAXNS);
    for ( i = 0; i < MAXNS; i++ ) {
        if ( _res._u._ext.nsaddrs[i] ) {
            free(_res._u._ext.nsaddrs[i]);
        }
        /* set to MAXNS indicates unused? */
        _res._u._ext.nsmap[i] = MAXNS;
        _res._u._ext.nsaddrs[i] = NULL;
        //XXX this was only in v6 branch, now we try doing it for all
        _res._u._ext.nssocks[i] = -1;
    }

    /* add nameservers till we run out or hit MAXNS valid ones */
    for ( i = 0; i < count && nservall < MAXNS; i++ ) {
        assert(servers[i]);
        Log(LOG_DEBUG, "Adding nameserver %s", servers[i]);

        ss = malloc(sizeof(struct sockaddr_storage));
        memset(ss, 0, sizeof(struct sockaddr_storage));

        /* try to convert address string to IPv4 address */
        if ( inet_pton(AF_INET, servers[i],
                    &((struct sockaddr_in*)ss)->sin_addr) > 0 ) {
            struct sockaddr_in *sa = (struct sockaddr_in*)ss;
            sa->sin_family = AF_INET;
            sa->sin_port = htons(53);
            _res.nsaddr_list[nservall] = *sa;
            _res._u._ext.nsaddrs[nservall] = (struct sockaddr_in6*)sa;//XXX add it to extended too
            _res._u._ext.nsmap[nservall] = nserv; // XXX
            nserv++;
            nservall++;

        } else if ( inet_pton(AF_INET6, servers[i],
                    &((struct sockaddr_in6*)ss)->sin6_addr) > 0 ) {
            /* if it fails then try to convert it to IPv6 address */
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)ss;
            sa6->sin6_family = AF_INET6;
            sa6->sin6_port = htons(53);
            _res._u._ext.nsaddrs[nservall] = sa6;
            /* set to MAXNS + 1 indicates IPv6 address */
            _res._u._ext.nsmap[nservall] = MAXNS + 1;
            nservall++;

        } else {
            Log(LOG_WARNING, "Failed to convert nameserver %s into an address",
                    servers[i]);
            free(ss);
        }
    }

    /* record total number of nameservers, and total number of IPv6 ones */
    _res.nscount = nservall;
    _res._u._ext.nscount = nservall; // XXX should this be nservall or nserv?
    if (nservall - nserv > 0) {
        _res._u._ext.nscount6 = nservall - nserv;
        _res.ipv6_unavail = 0;
    }

    return 1;
}



