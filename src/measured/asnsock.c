#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>

#include "asn.h"
#include "asnsock.h"
#include "ampresolv.h"
#include "debug.h"



/*
 * Convert a plain text ASN response into an address structure, adding it to
 * the result trie.
 */
static void add_parsed_line(struct amp_asn_info *info, struct iptrie *result,
        char *line) {

    char *asptr, *addrptr, *addrstr;
    struct sockaddr_storage addr;
    uint64_t as;
    uint8_t prefix;

    memset(&addr, 0, sizeof(struct sockaddr_storage));

    /* the ASN is the first part of the line */
    as = atoi(strtok_r(line, "|", &asptr));

    /*
     * the address portion is next, because we are forcing all cached values
     * to be /24s or /64s, this is what we are going to use instead
     * of the actual network prefix
     */
    addrstr = strtok_r(NULL, "|", &asptr);
    /* trim the whitespace from front and back */
    addrstr = strtok_r(addrstr, " ", &addrptr);

    /* turn the address string into a useful sockaddr */
    if ( inet_pton(AF_INET, addrstr,
                &((struct sockaddr_in*)&addr)->sin_addr) ) {
        addr.ss_family = AF_INET;
        prefix = 24;
    } else if ( inet_pton(AF_INET6, addrstr,
                &((struct sockaddr_in6*)&addr)->sin6_addr)) {
        addr.ss_family = AF_INET6;
        prefix = 64;
    } else {
        assert(0);
    }

    /* add to the result set */
    iptrie_add(result, (struct sockaddr*)&addr, prefix, as);

    /* add to the global cache */
    if ( info != NULL ) {
        pthread_mutex_lock(info->mutex);
        iptrie_add(info->trie, (struct sockaddr*)&addr, prefix, as);
        pthread_mutex_unlock(info->mutex);
    }
}



/*
 * Try to extract complete lines containing plain text ASN responses from
 * the result buffer.
 */
static void process_buffer(struct amp_asn_info *info, struct iptrie *result,
        char *buffer, int buflen, int *offset, int *outstanding) {

    char *line;
    char *lineptr = NULL;
    int linelen;

    while ( index(buffer, '\n') != NULL ) {
        /*
         * Always call strtok_r with all the parameters because we
         * modify buffer at the end of the loop.
         */
        line = strtok_r(buffer, "\n", &lineptr);
        linelen = strlen(line) + 1;

        /* ignore the header or any error messages */
        if ( strncmp(line, "Bulk", 4) == 0 || strncmp(line, "Error", 5) == 0 ) {
            memmove(buffer, buffer + linelen, buflen - linelen);
            *offset = *offset - linelen;
            buffer[*offset] = '\0';
            continue;
        }

        /* parse the response line and add a new result item */
        add_parsed_line(info, result, line);

        /* move the remaining data to the front of the buffer */
        memmove(buffer, buffer + linelen, buflen - linelen);
        *offset = *offset - linelen;
        buffer[*offset] = '\0';

        (*outstanding)--;
    }
}



/*
 * Send back all the results of ASN resolution
 */
static int return_asn_list(iptrie_node_t *root, void *data) {

    int addrlen;
    int fd = *(int*)data;

    switch ( root->address->sa_family ) {
        case AF_INET: addrlen = sizeof(struct sockaddr_in); break;
        case AF_INET6: addrlen = sizeof(struct sockaddr_in6); break;
        default: Log(LOG_WARNING, "Unknown address family in ASN list");
                 return -1;
    };

    if ( send(fd, &root->as, sizeof(root->as), MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to return ASN number: %s", strerror(errno));
        return -1;
    }

    if ( send(fd, &root->prefix, sizeof(root->prefix), MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to return prefix: %s", strerror(errno));
        return -1;
    }

    if ( send(fd, &root->address->sa_family, sizeof(uint16_t),
                MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to return family: %s", strerror(errno));
        return -1;
    }

    if ( send(fd, root->address, addrlen, MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to return address: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Write an IP address in plain text to the socket connected to the whois
 * server, asking it to look up the AS number.
 */
static int write_asn_request(int fd, struct sockaddr *address) {
    char addrstr[INET6_ADDRSTRLEN + 1];
    unsigned int sent, left;
    int bytes;
    void *addrptr;

    Log(LOG_DEBUG, "Sending whois request");

    /* convert IP address into a string for the query */
    switch ( address->sa_family ) {
        case AF_INET: addrptr = &((struct sockaddr_in*)address)->sin_addr;
                      break;
        case AF_INET6: addrptr = &((struct sockaddr_in6*)address)->sin6_addr;
                       break;
        default: Log(LOG_WARNING, "Invalid address family"); return -1;
    };

    inet_ntop(address->sa_family, addrptr, addrstr, INET6_ADDRSTRLEN);

    /* need a newline between addresses, null terminate too */
    addrstr[strlen(addrstr) + 1] = '\0';
    addrstr[strlen(addrstr)] = '\n';

    sent = 0;
    left = strlen(addrstr);

    /* deal with annoying partial sends, make sure the whole buffer goes */
    while ( sent < strlen(addrstr) ) {
        if ( (bytes = send(fd, addrstr + sent, left, 0)) < 0 ) {
            Log(LOG_WARNING, "Error writing to whois socket: %s",
                    strerror(errno));
            return -1;
        }
        sent += bytes;
        left -= bytes;
    }

    return 0;
}



/*
 * Read the available ASN data (up to one less than the available
 * space, so we have room to null terminate the buffer).
 */
static int read_asn_request(int fd, char *buffer, int buflen, int *offset) {
    int bytes;

    if ( (bytes = recv(fd, buffer + *offset, buflen - *offset - 1, 0)) < 1 ) {
        /* error or end of file */
        if ( bytes == 0 ) {
            Log(LOG_DEBUG, "Finished receiving data from whois server");
        } else {
            Log(LOG_WARNING, "Error receiving data from whois server");
        }
        return -1;
    }

    *offset += bytes;

    /*
     * We use string functions looking for newlines in the buffer,
     * so null terminate it in case we end up travelling off the end.
     */
    buffer[*offset] = '\0';

    return 0;
}



/*
 *
 */
static int check_whois_connection(int *whois_fd) {
    /* if we haven't already tried, connect to the whois server */
    if ( *whois_fd == -1 ) {
        *whois_fd = connect_to_whois_server();
    }

    /* we've tried and failed to connect, don't bother any more */
    if ( *whois_fd < 0 ) {
        Log(LOG_DEBUG, "whois connection unavailable, ignoring");
        return -1;
    }

    return 0;
}



/*
 * TODO be smarter about this, we don't need to dump the whole thing
 */
static void check_refresh_cache(struct amp_asn_info *info) {
    pthread_mutex_lock(info->mutex);
    if ( time(NULL) > *info->refresh ) {
        Log(LOG_DEBUG, "Clearing ASN cache");
        iptrie_clear(info->trie);
        *info->refresh = time(NULL) + MIN_ASN_CACHE_REFRESH +
            (rand() % MAX_ASN_CACHE_REFRESH_OFFSET);
        Log(LOG_DEBUG, "Next refresh at %d", *info->refresh);
    }
    pthread_mutex_unlock(info->mutex);
}



/*
 * Try to look up the ASN for an address in the local cache.
 */
static int check_asn_cache(struct amp_asn_info *info, struct iptrie *result,
        struct sockaddr *address) {
    int asn;
    int prefix;

    Log(LOG_DEBUG, "Checking ASN cache for address");

    pthread_mutex_lock(info->mutex);
    if ( (asn = iptrie_lookup_as(info->trie, address)) < 0 ) {
        pthread_mutex_unlock(info->mutex);
        Log(LOG_DEBUG, "Address not found in ASN cache");
        return -1;
    }
    pthread_mutex_unlock(info->mutex);

    Log(LOG_DEBUG, "Address found in ASN cache");

    if ( address->sa_family == AF_INET ) {
        prefix = 24;
    } else {
        prefix = 64;
    }

    /* add the values to our result trie */
    iptrie_add(result, address, prefix, asn);
    return 0;
}



/*
 * Read all the addresses from the local socket (from an AMP test) and build
 * them into a trie.
 */
static int fill_request_trie(int fd, struct iptrie *requests) {
    fd_set readset;
    int ready;
    struct sockaddr_storage addr;
    int length = 0;
    void *target = NULL;
    int prefix;
    struct timeval timeout;
    int bytes;

    while ( 1 ) {
        do {
            FD_ZERO(&readset);

            /* just in case the test process talking to us gets killed */
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            /* read addresses to lookup from this descriptor */
            FD_SET(fd, &readset);

            ready = select(fd + 1, &readset, NULL, NULL, &timeout);
        } while ( ready < 0 && errno == EINTR );

        if ( ready == 0 ) {
            Log(LOG_WARNING, "Timeout during select() for ASN data");
            return -1;
        }

        if ( ready < 0 ) {
            Log(LOG_WARNING, "Error in select() for ASN data: %s",
                    strerror(errno));
            return -1;
        }

        if ( FD_ISSET(fd, &readset) ) {
            /* read address family */
            if ( recv(fd, &addr.ss_family, sizeof(uint16_t), 0) <= 0 ) {
                Log(LOG_WARNING, "Error reading address family, aborting");
                return -1;
            }

            /* figure out how much we need to read to get the address */
            switch ( addr.ss_family ) {
                case AF_INET:
                    length = sizeof(struct in_addr);
                    target = &((struct sockaddr_in*)&addr)->sin_addr;
                    prefix = 24;
                    break;
                case AF_INET6:
                    length = sizeof(struct in6_addr);
                    target = &((struct sockaddr_in6*)&addr)->sin6_addr;
                    prefix = 64;
                    break;
                default:
                    /* if it's not INET or INET6 assume it is the end marker */
                    Log(LOG_DEBUG, "Got last address required for ASN lookups");
                    return 0;
            };

            /* read the right number of bytes for the address */
            if ( (bytes = recv(fd, target, length, 0)) <= 0 ) {
                Log(LOG_WARNING, "Error reading address, aborting");
                return -1;
            }

            Log(LOG_DEBUG, "Read %d bytes for address", bytes);

            /* add the address to the trie to be looked up later */
            iptrie_add(requests, (struct sockaddr*)&addr, prefix, 0);
        }
    }

    /* XXX never reached */
    Log(LOG_WARNING, "Broke out of fill_request_trie() loop unexpectedly");
    return -1;
}



static void *amp_asn_worker_thread(void *thread_data) {
    struct amp_asn_info *info = (struct amp_asn_info*)thread_data;
    struct iptrie result = { NULL, NULL };
    struct iptrie requests = { NULL, NULL };

    fd_set readset, writeset;
    int whois_fd = -1;
    int ready;
    int offset = 0;
    int buflen = 1024;//XXX define? and bigger
    char *buffer = calloc(1, buflen);
    int outstanding = 0;
    struct timeval timeout;
    iplist_t *list;

    Log(LOG_DEBUG, "Starting new asn resolution thread");

    /* periodically clear out the cache */
    check_refresh_cache(info);

    /* read all the addresses from the socket and build a trie from them */
    if ( fill_request_trie(info->fd, &requests) < 0 ) {
        Log(LOG_WARNING, "asn resolution thread failed to create request trie");
        goto end;
    }

    /* look up all the addresses in the cache or the whois server */
    for ( list = iptrie_to_list(&requests), outstanding = 0;
            list != NULL || outstanding > 0; /* no increment statement*/ ) {

        if ( list ) {
            /* first try to find address in cache */
            if ( check_asn_cache(info, &result, list->address) == 0 ) {
                list = list->next;
                continue;
            }

            /* if not in cache, check if can connect to the whois server */
            if ( check_whois_connection(&whois_fd) < 0 ) {
                list = list->next;
                continue;
            }
        }

        /* we have a connection, try looking up the ASN for the address */
        do {
            FD_ZERO(&readset);
            FD_ZERO(&writeset);

            if ( outstanding > 0 ) {
                FD_SET(whois_fd, &readset);
            }

            if ( list ) {
                FD_SET(whois_fd, &writeset);
            }

            /* it should never take 30s and we don't want to wait forever */
            timeout.tv_sec = 30;
            timeout.tv_usec = 0;
            ready = select(whois_fd + 1, &readset, &writeset, NULL, &timeout);

        } while ( ready < 0 && errno == EINTR );

        /* error, close the whois connection and just use the cache */
        if ( ready <= 0 ) {
            Log(LOG_WARNING, "Error while waiting for ASN data");
            close(whois_fd);
            whois_fd = WHOIS_UNAVAILABLE;
            if ( list ) list = list->next;
            outstanding = 0;
            continue;
        }

        /* we can write a new request, do so */
        if ( FD_ISSET(whois_fd, &writeset) ) {

            /* send the asn request to the whois server */
            if ( write_asn_request(whois_fd, list->address) < 0 ) {
                close(whois_fd);
                whois_fd = WHOIS_UNAVAILABLE;
                if ( list ) list = list->next;
                outstanding = 0;
                continue;
            }

            /* successfully sent, we expect to get a reply for it */
            outstanding++;
            list = list->next;
        }

        /* here is a result we previously asked for, read it */
        if ( FD_ISSET(whois_fd, &readset) ) {

            /* Read the available ASN data */
            if ( read_asn_request(whois_fd, buffer, buflen, &offset) < 0 ) {
                close(whois_fd);
                whois_fd = WHOIS_UNAVAILABLE;
                if ( list ) list = list->next;
                outstanding = 0;
                continue;
            }

            /* try to read any completed ASN results from the buffer */
            process_buffer(info, &result, buffer, buflen, &offset,&outstanding);
        }
    }

    if ( whois_fd != -1 ) {
        close(whois_fd);
    }
    Log(LOG_DEBUG, "Got all responses, sending them back");

    iptrie_on_all_leaves(&result, return_asn_list, &info->fd);

end:
    Log(LOG_DEBUG, "Tidying up after asn resolution thread");

    close(info->fd);
    iptrie_clear(&requests);
    iptrie_clear(&result);
    free(thread_data);
    free(buffer);

    Log(LOG_DEBUG, "asn resolution thread completed, exiting");

    pthread_exit(NULL);
}



/*
 * Accept a new connection on the local autonomous system resolution socket
 * and spawn a new thread to deal with the queries from the test process.
 */
void asn_socket_event_callback(
        __attribute__((unused))wand_event_handler_t *ev_hdl, int eventfd,
        void *data, __attribute__((unused))enum wand_eventtype_t ev) {

    int fd;
    pthread_t thread;
    struct amp_asn_info *info;

    Log(LOG_DEBUG, "Accepting for new asn connection");

    if ( (fd = accept(eventfd, NULL, NULL)) < 0 ) {
        Log(LOG_WARNING, "Failed to accept for asn resolution: %s",
                strerror(errno));
        return;
    }

    Log(LOG_DEBUG, "Accepted new asn connection on fd %d", fd);

    info = calloc(1, sizeof(struct amp_asn_info));
    info->trie = ((struct amp_asn_info*)data)->trie;
    info->mutex = ((struct amp_asn_info*)data)->mutex;
    info->refresh = ((struct amp_asn_info*)data)->refresh;
    info->fd = fd;

    /* create the thread and detach, we don't need to look after it */
    pthread_create(&thread, NULL, amp_asn_worker_thread, info);
    pthread_detach(thread);
}



/*
 *
 */
struct amp_asn_info* initialise_asn_info(void) {
    struct amp_asn_info *info;

    info = (struct amp_asn_info *) malloc(sizeof(struct amp_asn_info));

    info->fd = -1;

    info->refresh = malloc(sizeof(time_t));
    *info->refresh = time(NULL) + MIN_ASN_CACHE_REFRESH +
        (rand() % MAX_ASN_CACHE_REFRESH_OFFSET);

    Log(LOG_DEBUG, "ASN cache will be refreshed at %d", *info->refresh);

    info->trie = malloc(sizeof(struct iptrie));
    info->trie->ipv4 = NULL;
    info->trie->ipv6 = NULL;

    info->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(info->mutex, NULL);

    return info;
}



/*
 *
 */
void amp_asn_info_delete(struct amp_asn_info *info) {
    if ( info == NULL ) {
        return;
    }

    pthread_mutex_lock(info->mutex);
    iptrie_clear(info->trie);
    pthread_mutex_unlock(info->mutex);
    pthread_mutex_destroy(info->mutex);

    if ( info->mutex ) free(info->mutex);
    if ( info->refresh ) free(info->refresh);
    if ( info->trie ) free(info->trie);

    free(info);
}
