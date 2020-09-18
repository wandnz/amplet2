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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unbound.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

#include "ampresolv.h"
#include "debug.h"
#include "testlib.h"

/*
 * XXX filename and function inconsistency, lets try to tidy up the
 * differences between amp_resolver vs amp_resolve vs amp_resolv
 */



/*
 * Set up the unbound context that we will use to query (even if no nameservers
 * are specified, it will be able to cache results).
 */
struct ub_ctx *amp_resolver_context_init(char *servers[], int nscount,
        char *sourcev4, char *sourcev6) {

    struct ub_ctx *ctx;

    Log(LOG_DEBUG, "Initialising nameserver context with %d servers", nscount);

    /* create the context */
    if ( (ctx = ub_ctx_create()) == NULL ) {
        Log(LOG_WARNING, "Could not create unbound context\n");
        return NULL;
    }

    /* use threads for asynchronous resolving */
    if ( ub_ctx_async(ctx, 1) < 0 ) {
        Log(LOG_WARNING, "error enabling threading in resolver\n");
        return NULL;
    }

    if ( nscount == 0 ) {
        /* use the contents of /etc/resolv.conf */
        Log(LOG_DEBUG, "Using default nameservers from /etc/resolv.conf");
        ub_ctx_resolvconf(ctx, NULL);
    } else {
        int i;
        /* set the nameservers that we should query, if they are specified */
        for ( i = 0; i < nscount; i++ ) {
            Log(LOG_DEBUG, "Adding %s as nameserver", servers[i]);
            if ( ub_ctx_set_fwd(ctx, servers[i]) < 0 ) {
                Log(LOG_WARNING, "error setting resolver address to %s\n",
                        servers[i]);
            }
        }
    }

    /* use only the given outgoing interfaces if they have been specified */
    if ( sourcev4 ) {
        ub_ctx_set_option(ctx, "outgoing-interface:", sourcev4);
    }

    if ( sourcev6 ) {
        ub_ctx_set_option(ctx, "outgoing-interface:", sourcev6);
    }

    return ctx;
}



/*
 * Build a struct addrinfo from one set of data returned by the unbound query.
 */
static struct addrinfo* build_addrinfo(int qtype, char *qname, char *data,
        int datalen) {

        struct addrinfo *item = calloc(1, sizeof(struct addrinfo));

        switch ( qtype ) {
            case 0x01:
                item->ai_family = AF_INET;
                if ( data ) {
                    item->ai_addrlen = sizeof(struct sockaddr_in);
                    item->ai_addr = calloc(1, item->ai_addrlen);
                    item->ai_addr->sa_family = AF_INET;
                    memcpy(&((struct sockaddr_in*)item->ai_addr)->sin_addr,
                            data, datalen);
                }
                break;

            case 0x1c:
                item->ai_family = AF_INET6;
                if ( data ) {
                    item->ai_addrlen = sizeof(struct sockaddr_in6);
                    item->ai_addr = calloc(1, item->ai_addrlen);
                    item->ai_addr->sa_family = AF_INET6;
                    memcpy(&((struct sockaddr_in6*)item->ai_addr)->sin6_addr,
                            data, datalen);
                }
                break;

            default:
                item->ai_family = AF_UNSPEC;
                break;
        };

        item->ai_canonname = strdup(qname);

        return item;
}



/*
 * Deal with a DNS response being returned - take as many addresses as we are
 * allowed and convert them into addrinfo structs for the caller to use.
 * Any thread could end up calling this for incoming data, but the addrlist
 * is contained in the callback data so it doesn't matter, the addresses will
 * end up on the right list.
 */
static void amp_resolve_callback(void *d, int err, struct ub_result *result) {
    struct amp_resolve_data *data = (struct amp_resolve_data *)d;
    struct addrinfo *item;
    int qcount;
    int i;

    assert(result);

    /* lock the data block, we are about to update the address list */
    pthread_mutex_lock(data->lock);

    assert(data->qcount > 0);

    if ( err != 0 || !result->havedata ) {
        Log(LOG_DEBUG, "Failed query %s (%x)", result->qname, result->qtype);
        if ( err != 0 ) {
            Log(LOG_DEBUG, "Resolve error: %s\n", ub_strerror(err));
        } else {
            Log(LOG_DEBUG, "No results returned");
        }
    } else {
        Log(LOG_DEBUG, "Got a DNS response for %s (%x)", result->qname,
                result->qtype);

        /*
         * Loop over all the results until we hit max or run out of results.
         * Note that max is shared between the A and AAAA queries (if present)
         * so that only that many results will be returned for the one name.
         */
        for ( i = 0; result->data[i] != NULL &&
                (data->max == -1 || data->max > 0); i++ ) {

            item = build_addrinfo(result->qtype, result->qname,
                    result->data[i], result->len[i]);
            item->ai_next = *data->addrlist;
            *data->addrlist = item;

            /* consume a target if we care about the maximum number of them */
            if ( data->max > 0 ) {
                data->max--;
            }
        }

        data->status = AMP_RESOLVE_OK;
    }

    /* get outstanding queries for this name while we still have it locked */
    qcount = --data->qcount;

    pthread_mutex_unlock(data->lock);

    /*
     * no outstanding queries for this name - make sure we got some sort of
     * result and then free the data block
     */
    if ( qcount <= 0 ) {
        if ( data->status != AMP_RESOLVE_OK ) {
            Log(LOG_DEBUG, "No results for %s, creating dummy entries",
                    result->qname);

            if ( data->family == AF_INET || data->family == AF_UNSPEC ) {
                item = build_addrinfo(0x01, result->qname, NULL, 0);
                item->ai_next = *data->addrlist;
                *data->addrlist = item;
            }

            if ( data->family == AF_INET6 || data->family == AF_UNSPEC ) {
                item = build_addrinfo(0x1c, result->qname, NULL, 0);
                item->ai_next = *data->addrlist;
                *data->addrlist = item;
            }
        }

        free(data);
    }

    if ( result ) {
        ub_resolve_free(result);
    }
}



/*
 * Add a request to the queue, querying for IPv4 and IPV6 addresses as desired.
 * TODO rename this? mostly used internally but testmain.c uses it too
 */
void amp_resolve_add(struct ub_ctx *ctx, struct addrinfo **res,
        pthread_mutex_t *addrlist_lock, char *name, int family, int max) {

    struct amp_resolve_data *data;
    struct addrinfo *addr;

    assert(ctx);
    assert(res);
    assert(name);

    Log(LOG_DEBUG, "Adding resolve request for %s", name);

    /* check if this is a numeric address already and doesn't need resolving */
    if ( (addr = get_numeric_address(name, NULL)) ) {
        struct addrinfo *keeper = calloc(1, sizeof(struct addrinfo));
        /*
         * It is, copy the data into our own struct addrinfo that we have
         * allocated and prepend it to the result list.
         * TODO this double handling is terrible and needs to be fixed, but
         * it's much easier if we can just manage all the memory rather than
         * having getaddrinfo() allocated blocks mixed in with our own.
         */
        keeper->ai_flags = addr->ai_flags;
        keeper->ai_family = addr->ai_family;
        keeper->ai_socktype = addr->ai_socktype;
        keeper->ai_protocol = addr->ai_protocol;
        keeper->ai_addrlen = addr->ai_addrlen;
        keeper->ai_addr = calloc(1, keeper->ai_addrlen);

        assert(keeper->ai_addrlen > 0);
        assert(keeper->ai_addr);

        memcpy(keeper->ai_addr, addr->ai_addr, keeper->ai_addrlen);
        keeper->ai_canonname = strdup(name);
        keeper->ai_next = *res;
        *res = keeper;

        /* free the getaddrinfo() allocated memory */
        freeaddrinfo(addr);
        return;
    }

    /* otherwise send it to the resolver to be looked up */
    data = calloc(1, sizeof(struct amp_resolve_data));
    data->status = AMP_RESOLVE_WAITING;

    /* keep a reference to the list of addresses we are building up */
    data->addrlist = res;

    /* create a mutex to make sure we don't mess up our addrlist */
    data->lock = addrlist_lock;

    /*
     * Track how many queries we have that are using this data block, if we
     * share it between multiple queries we have to know when it is no longer
     * being used. This lets us share the max value between queries with the
     * same name and different address family.
     */
    data->family = family;
    if ( data->family == AF_UNSPEC ) {
        data->qcount = 2;
    } else {
        data->qcount = 1;
    }

    /*
     * Track a maximum number of address to resolve, shared between both IPv4
     * and IPv6 for this name. If the maximum is zero, there is no limit.
     */
    if ( max > 0 ) {
        data->max = max;
    } else {
        data->max = -1; // XXX can we push this back to the schedule code?
    }

    /* query for the A record */
    /* TODO only query if there is a useful IPv4 address? */
    if ( family == AF_UNSPEC || family == AF_INET ) {
        ub_resolve_async(ctx, name, 0x01, 0x01, (void*)data,
                amp_resolve_callback, NULL);
    }

    /* query for the AAAA record */
    /* TODO only query if there is a useful IPv6 address? */
    if ( family == AF_UNSPEC || family == AF_INET6 ) {
        ub_resolve_async(ctx, name, 0x1c, 0x01, (void*)data,
                amp_resolve_callback, NULL);
    }
}



/*
 * Free a chain of addrinfo structs, in a similar way to how freeaddrinfo works.
 */
void amp_resolve_freeaddr(struct addrinfo *addrlist) {
    struct addrinfo *item;

    while ( addrlist != NULL ) {
        item = addrlist;
        addrlist = addrlist->ai_next;

        if ( item->ai_addr ) {
            free(item->ai_addr);
        }

        if ( item->ai_canonname ) {
            free(item->ai_canonname);
        }

        free(item);
    }
}



/*
 * Create a connection to the local resolver/cache for a test to use.
 */
int amp_resolver_connect(char *path) {
    struct sockaddr_un addr;
    int sock;

    Log(LOG_DEBUG, "Connecting to local socket '%s' for name resolution", path);

    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, UNIX_PATH_MAX, "%s", path);

    /* connect to the unix socket the cache is listening on */
    if ( (sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ) {
        Log(LOG_WARNING, "Failed to open local socket for name resolution: %s",
                strerror(errno));
        return -1;
    }

    if ( connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
        if ( errno != ENOENT ) {
            Log(LOG_WARNING,
                    "Failed to open local socket for name resolution: %s",
                    strerror(errno));
        }
        return -1;
    }

    return sock;
}



/*
 * TODO rename this function so it doesn't have _new. It will generally
 * replace the existing amp_resolve_add() function. This is the one that
 * is called by test clients.
 */
int amp_resolve_add_new(int fd, resolve_dest_t *resolve) {
    struct amp_resolve_query info;

    info.namelen = strlen(resolve->name) + 1;
    info.count = resolve->count;
    info.family = resolve->family;

    /* send the supporting metadata about name length, family etc */
    if ( send(fd, &info, sizeof(info), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send resolution query info: %s",
                strerror(errno));
        return -1;
    }

    /* send namelen bytes containing the name to resolve */
    if ( send(fd, resolve->name, info.namelen, 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send resolution query: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}



/*
 *
 */
int amp_resolve_flag_done(int fd) {
    struct amp_resolve_query info;

    info.namelen = 0;
    info.count = 0;
    info.family = 0;

    /* send the supporting metadata about name length, family etc */
    if ( send(fd, &info, sizeof(info), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send resolution query info: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Get a list of addrinfo structs that is the result of all the queries
 * that were sent to this thread. This will block until all the queries
 * complete or time out.
 */
struct addrinfo *amp_resolve_get_list(int fd) {
    struct addrinfo *addrlist = NULL;
    struct addrinfo item;
    char name[MAX_DNS_NAME_LEN];
    uint8_t more;
    uint8_t namelen;

    Log(LOG_DEBUG, "Waiting for address list");

    /* everything we read should be the result of a name lookup */
    while ( 1 ) {
        struct addrinfo *tmp;
        if ( recv(fd, &item, sizeof(struct addrinfo), 0) <= 0 ) {
            break;
        }

        tmp = calloc(1, sizeof(struct addrinfo));
        tmp->ai_flags = item.ai_flags;
        tmp->ai_family = item.ai_family;
        tmp->ai_socktype = item.ai_socktype;
        tmp->ai_protocol = item.ai_protocol;
        tmp->ai_addrlen = item.ai_addrlen;

        /* there might not be an address for this name */
        if ( tmp->ai_addrlen > 0 ) {
            tmp->ai_addr = calloc(1, tmp->ai_addrlen);
            if ( recv(fd, tmp->ai_addr, tmp->ai_addrlen, 0) <= 0 ) {
                free(tmp);
                break;
            }
        }

        if ( recv(fd, &namelen, sizeof(namelen), 0) <= 0 ) {
            free(tmp);
            break;
        }

        assert(namelen > 1);

        if ( recv(fd, name, namelen, 0) <= 0 ) {
            free(tmp);
            break;
        }
        tmp->ai_canonname = strdup(name);
        assert(tmp->ai_canonname);

        if ( recv(fd, &more, sizeof(more), 0) <= 0 ) {
            free(tmp->ai_canonname);
            free(tmp);
            break;
        }

        /* add the item to the front of the list once it is complete */
        tmp->ai_next = addrlist;
        addrlist = tmp;

        if ( !more ) {
            break;
        }
    }

    close(fd); //XXX do this here or at next level up in the test?

    return addrlist;
}

