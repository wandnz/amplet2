/* for mempcpy() */
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#include "global.h"
#include "ampresolv.h"
#include "debug.h"
#include "testlib.h"

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
