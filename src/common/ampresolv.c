/* for mempcpy() */
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unbound.h>

#include "global.h"
#include "ampresolv.h"
#include "debug.h"
#include "testlib.h"



/*
 * Set up the unbound context that we will use to query (even if no nameservers
 * are specified, it will be able to cache results).
 */
struct ub_ctx *amp_resolve_init(char *servers[], int nscount, char *sourcev4,
        char *sourcev6) {

    struct ub_ctx *ctx;
    int i;

    Log(LOG_DEBUG, "Initialising nameserver context with %d servers", nscount);

    /* create the context */
    if ( (ctx = ub_ctx_create()) == NULL ) {
        Log(LOG_WARNING, "Could not create unbound context\n");
        return NULL;
    }

    /* use threads rather than full processes for async resolving */
    if ( ub_ctx_async(ctx, 1) < 0 ) {
        Log(LOG_WARNING, "error enabling threading in resolver\n");
        return NULL;
    }

    /* set the nameservers that we should query, if they are specified */
    for ( i = 0; i < nscount; i++ ) {
        Log(LOG_DEBUG, "Adding %s as nameserver", servers[i]);
        if ( ub_ctx_set_fwd(ctx, servers[i]) < 0 ) {
            Log(LOG_WARNING, "error setting forward address to %s\n",
                    servers[i]);
        }
    }

    /* use only the given outgoing interfaces if they have been specified */
    if ( sourcev4 ) {
        ub_ctx_set_option(ctx, "outgoing-interface", sourcev4);
    }

    if ( sourcev6 ) {
        ub_ctx_set_option(ctx, "outgoing-interface", sourcev6);
    }

    return ctx;
}



/*
 * Deal with a DNS response being returned - take as many addresses as we are
 * allowed and convert them into addrinfo structs for the caller to use.
 */
static void amp_resolve_callback(void *d, int err, struct ub_result *result) {
    struct amp_resolve_data *data = (struct amp_resolve_data *)d;
    struct addrinfo *item;
    int i;

    Log(LOG_DEBUG, "Got a DNS response for %s (%x)", result->qname,
            result->qtype);

    if ( err != 0 ) {
        Log(LOG_DEBUG, "resolve error: %s\n", ub_strerror(err));
        data->outstanding--;
        if ( data->outstanding <= 0 ) {
            free(data);
        }
        return;
    }

    if ( !result->havedata ) {
        Log(LOG_DEBUG, "no results for query");
        data->outstanding--;
        if ( data->outstanding <= 0 ) {
            free(data);
        }
        return;
    }

    /*
     * Loop over all the results until we hit max or run out of results. Note
     * that max is shared between the A and AAAA queries (if present) so that
     * only that many results will be returned for the one name.
     */
    for ( i = 0; result->data[i] != NULL &&
            (data->max == -1 || data->max > 0); i++ ) {

        item = calloc(1, sizeof(struct addrinfo));

        /* looks like we have to build the whole thing ourselves */
        switch ( result->qtype ) {
            case 0x01: item->ai_family = AF_INET;
                       item->ai_addrlen = sizeof(struct sockaddr_in);
                       item->ai_addr = calloc(1, item->ai_addrlen);
                       memcpy(&((struct sockaddr_in*)item->ai_addr)->sin_addr,
                               result->data[i], result->len[i]);
                       break;
            case 0x1c: item->ai_family = AF_INET6;
                       item->ai_addrlen = sizeof(struct sockaddr_in6);
                       item->ai_addr = calloc(1, item->ai_addrlen);
                       memcpy(&((struct sockaddr_in6*)item->ai_addr)->sin6_addr,
                               result->data[i], result->len[i]);
                       break;
            default: item->ai_family = AF_UNSPEC;
                     item->ai_addrlen = 0;
                     item->ai_addr = NULL;
                     break;
        };

        item->ai_canonname = strdup(result->qname); /* vs canonname? */

        /* prepend this item to the list */
        item->ai_next = *data->addrlist;
        *data->addrlist = item;

        if ( data->max > 0 ) {
            data->max--;
        }
    }

    data->outstanding--;
    if ( data->outstanding <= 0 ) {
        free(data);
    }

    ub_resolve_free(result);
}



/*
 * Add a request to the queue, querying for IPv4 and IPV6 addresses as desired.
 */
void amp_resolve_add(struct ub_ctx *ctx, struct addrinfo **res, char *name,
        int family, int max) {

    struct amp_resolve_data *data = calloc(1, sizeof(struct amp_resolve_data));

    Log(LOG_DEBUG, "Adding resolve request for %s", name);

    /* keep a reference to the list of addresses we are building up */
    data->addrlist = res;

    /* track how many queries we have that are using this data block */
    data->outstanding = 0;

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
        data->outstanding++;
        ub_resolve_async(ctx, name, 0x01, 0x01, (void*)data,
                amp_resolve_callback, NULL);
    }

    /* query for the AAAA record */
    /* TODO only query if there is a useful IPv6 address? */
    if ( family == AF_UNSPEC || family == AF_INET6 ) {
        data->outstanding++;
        ub_resolve_async(ctx, name, 0x1c, 0x01, (void*)data,
                amp_resolve_callback, NULL);
    }
}



/*
 * Wait for all addresses to be resolved. This function probably isn't really
 * needed, but helps hide the implementation details I guess.
 */
void amp_resolve_wait(struct ub_ctx *ctx) {
    Log(LOG_DEBUG, "Waiting for outstanding DNS requests");
    ub_wait(ctx);
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

