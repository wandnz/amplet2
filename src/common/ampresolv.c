#include <string.h>
#include <stdlib.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unbound.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>

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
    int i;

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
 * Any thread could end up calling this for incoming data, but the addrlist
 * is contained in the callback data so it doesn't matter, the addresses will
 * end up on the right list.
 */
static void amp_resolve_callback(void *d, int err, struct ub_result *result) {
    struct amp_resolve_data *data = (struct amp_resolve_data *)d;
    struct addrinfo *item;
    int qcount;
    int i;

    Log(LOG_DEBUG, "Got a DNS response for %s (%x)", result->qname,
            result->qtype);

    /* lock the data block, we are about to update the address list */
    pthread_mutex_lock(data->lock);

    assert(data->qcount > 0);
    assert(*data->remaining > 0);

    /* shared counter to track outstanding queries for this test */
    (*data->remaining)--;

    if ( err != 0 || !result->havedata ) {
        if ( err != 0 ) {
            Log(LOG_DEBUG, "resolve error: %s\n", ub_strerror(err));
        } else {
            Log(LOG_DEBUG, "no results for query");
        }

        goto end;
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
            default: Log(LOG_WARNING, "Unknown query response type");
                     pthread_mutex_unlock(data->lock);
                     assert(0);
                     break;
        };

        assert(item->ai_addr);
        assert(result->qname);

        item->ai_canonname = strdup(result->qname); /* vs canonname? */

        /* prepend this item to the list */
        item->ai_next = *data->addrlist;
        *data->addrlist = item;

        if ( data->max > 0 ) {
            data->max--;
        }
    }

end:
    /* get outstanding queries for this name while we still have it locked */
    qcount = --data->qcount;

    pthread_mutex_unlock(data->lock);

    /* no outstanding queries for this name, can free the data block */
    if ( qcount <= 0 ) {
        free(data);
    }

    ub_resolve_free(result);
}



/*
 * Add a request to the queue, querying for IPv4 and IPV6 addresses as desired.
 * TODO rename this? mostly used internally but testmain.c uses it too
 */
void amp_resolve_add(struct ub_ctx *ctx, struct addrinfo **res,
        pthread_mutex_t *addrlist_lock, char *name, int family, int max,
        int *remaining) {

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
    if ( family == AF_UNSPEC ) {
        data->qcount = 2;
    } else {
        data->qcount = 1;
    }

    /*
     * Track how many queries are outstanding for this test process. When they
     * are all complete, the test itself can begin.
     */
    data->remaining = remaining;
    *data->remaining += data->qcount;

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
 * Wait for all names used by this test to be resolved.
 */
void amp_resolve_wait(struct ub_ctx *ctx, pthread_mutex_t *lock,
        int *remaining) {
    int fd;
    int ready;
    fd_set readset;
    struct timeval timeout;

    assert(ctx);
    assert(lock);
    assert(remaining);

    Log(LOG_DEBUG, "Waiting for outstanding DNS requests");

    /* using the file descriptor directly lets us use select() for timeouts */
    if ( (fd = ub_fd(ctx)) < 0 ) {
        Log(LOG_WARNING, "Failed to get resolver file descriptor");
        return;
    }

    do {
	/* fd sets are undefined after an error, so set them every time */
	FD_ZERO(&readset);
        FD_SET(fd, &readset);

        /*
         * Reset the timeout, even if we had an error. Not worth the hassle
         * of calculating how much time was left when error occurred.
         */
        timeout.tv_sec = 0;
        timeout.tv_usec = MAX_DNS_POLL_USEC;

        ready = select(fd+1, &readset, NULL, NULL, &timeout);

        /* if the fd is available for reading, process the callbacks */
        if ( ready > 0 ) {
            ub_process(ctx);
        }

        /*
         * Check if any of the threads have finished processing data for this
         * particular test. We can stop waiting as soon as all of our names
         * have been resolved.
         */
        pthread_mutex_lock(lock);
        if ( *remaining <= 0 ) {
            pthread_mutex_unlock(lock);
            break;
        }
        pthread_mutex_unlock(lock);

    } while ( ready >= 0 || (ready < 0 && errno == EINTR) );

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
        Log(LOG_WARNING, "Failed to open local socket for name resolution: %s",
                strerror(errno));
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
    info.more = (resolve->next) ? 1 : 0;

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
        tmp->ai_addr = calloc(1, tmp->ai_addrlen);

        assert(tmp->ai_addrlen > 0);
        assert(tmp->ai_addr);

        if ( recv(fd, tmp->ai_addr, tmp->ai_addrlen, 0) <= 0 ) {
            free(tmp);
            break;
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

