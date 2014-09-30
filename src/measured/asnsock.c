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

#include "asn.h"
#include "asnsock.h"
#include "ampresolv.h"
#include "debug.h"




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



/* send back all the results of ASN resolution */
static void return_asn_list(iptrie_node_t *root, void *data) {

    int addrlen;
    int fd = *(int*)data;

    switch ( root->address->sa_family ) {
        case AF_INET: addrlen = sizeof(struct sockaddr_in); break;
        case AF_INET6: addrlen = sizeof(struct sockaddr_in6); break;
        default: return;
    };

    if ( send(fd, &root->as, sizeof(root->as), MSG_NOSIGNAL) < 0 ) {
        //XXX better not leave these empty without proper error handling!
    }

    if ( send(fd, &root->prefix, sizeof(root->prefix), MSG_NOSIGNAL) < 0 ) {
        //XXX
    }

    if ( send(fd, &root->address->sa_family, sizeof(uint16_t),
                MSG_NOSIGNAL) < 0 ) {
        //XXX
    }

    if ( send(fd, root->address, addrlen, MSG_NOSIGNAL) < 0 ) {
        //XXX
    }
}



static void *amp_asn_worker_thread(void *thread_data) {
    struct amp_asn_info *info = (struct amp_asn_info*)thread_data;
    struct iptrie result = { NULL, NULL };
    char addrstr[INET6_ADDRSTRLEN + 1];
    int bytes;

    fd_set readset, writeset;
    int whois_fd = -1;
    int max_fd;
    int ready;
    char *buffer = NULL;
    int index;
    int buflen = 1024;//XXX define? and bigger
    struct sockaddr_storage addr;
    void *target = NULL;
    int length = 0;
    int asn;
    int outstanding;

    Log(LOG_DEBUG, "Starting new asn resolution thread");

    /* XXX smaller than planned so it will fill while testing */
    buffer = calloc(1, buflen);
    index = 0;
    outstanding = 0;
    memset(&addr, 0, sizeof(addr));

    pthread_mutex_lock(info->mutex);
    if ( time(NULL) > *info->refresh ) {
        Log(LOG_DEBUG, "Clearing ASN cache");
        iptrie_clear(info->trie);
        *info->refresh = time(NULL) + MIN_ASN_CACHE_REFRESH +
            (rand() % MAX_ASN_CACHE_REFRESH_OFFSET);
        Log(LOG_DEBUG, "Next refresh at %d", *info->refresh);
    }
    pthread_mutex_unlock(info->mutex);

    while ( 1 ) {
        FD_ZERO(&readset);
        FD_ZERO(&writeset);

        /* read addresses to lookup from this descriptor */
        FD_SET(info->fd, &readset);

        /* read and write whois data from/to this descriptor */
        if ( whois_fd != -1 ) {
            FD_SET(whois_fd, &readset);
            //FD_SET(whois_fd, &writeset);
        }

        max_fd = (info->fd > whois_fd) ? info->fd : whois_fd;
        ready = select(max_fd + 1, &readset, &writeset, NULL, NULL);

        if ( ready < 0 && errno != EINTR ) {
            break;
        }

        if ( FD_ISSET(info->fd, &readset) ) {
            /* local connection with an address for us to look up */

            /* read address family */
            if ( recv(info->fd, &addr.ss_family, sizeof(uint16_t), 0) <= 0 ) {
                Log(LOG_WARNING, "Error reading address family, aborting");
                break;
            }

            if ( addr.ss_family != AF_INET && addr.ss_family != AF_INET6 ) {
                /* no more ASNs need to be resolved */
                Log(LOG_DEBUG, "Got all requests, waiting for responses");
                if ( whois_fd != -1 ) {
                    send(whois_fd, "end\n", strlen("end\n"), 0);
                }
                if ( outstanding == 0 ) {
                    break;
                }
                continue;
            }

            switch ( addr.ss_family ) {
                case AF_INET:
                    length = sizeof(struct in_addr);
                    target = &((struct sockaddr_in*)&addr)->sin_addr;
                    break;
                case AF_INET6:
                    length = sizeof(struct in6_addr);
                    target = &((struct sockaddr_in6*)&addr)->sin6_addr;
                    break;
            };

            if ( (bytes = recv(info->fd, target, length, 0)) <= 0 ) {
                Log(LOG_WARNING, "Error reading address, aborting");
                break;
            }

            Log(LOG_DEBUG, "Read %d bytes for address", bytes);

            /* see if ASN for address has already been fetched */
            pthread_mutex_lock(info->mutex);
            if ( (asn = iptrie_lookup_as(info->trie,
                            (struct sockaddr*)&addr)) >= 0 ) {
                int prefix;
                pthread_mutex_unlock(info->mutex);

                if ( addr.ss_family == AF_INET ) {
                    prefix = 24;
                } else {
                    prefix = 64;
                }

                /* add the values to our result trie */
                iptrie_add(&result, (struct sockaddr*)&addr, prefix, asn);
                continue;
            }
            pthread_mutex_unlock(info->mutex);

            /* not found, need to query - convert to a string for the query */
            inet_ntop(addr.ss_family, target, addrstr, INET6_ADDRSTRLEN);

            /* need a newline between addresses, null terminate too */
            addrstr[strlen(addrstr) + 1] = '\0';
            addrstr[strlen(addrstr)] = '\n';

            /* write this query and go back for more */
            /* XXX just like netcat, we don't care to select on the
             * writing file descriptor? Should we?
             */
            if ( whois_fd == -1 ) {
                whois_fd = connect_to_whois_server();
                if ( whois_fd == -1 ) {
                    /* for now, let's just give up if this fails */
                    break;
                }
            }

            if ( send(whois_fd, addrstr, strlen(addrstr), 0) < 0 ) {
                printf("error writing to whois socket\n");
            }
            outstanding++;
        }

        if ( whois_fd != -1 && FD_ISSET(whois_fd, &readset) ) {
            char *line;
            char *lineptr = NULL;
            int linelen;

            /* read the available ASN data */
            if ( (bytes = recv(whois_fd, buffer, buflen - index, 0)) < 1 ) {
                /* error or end of file */
                break;
            }

            index += bytes;

            /*
             * Only deal with whole lines of text. Also, always call strtok_r
             * with all the parameters because we modify buffer at the end
             * of the loop.
             */
            while ( (line = strtok_r(buffer, "\n", &lineptr)) != NULL ) {

                linelen = strlen(line) + 1;

                /* ignore the header or any error messages */
                if ( strncmp(line, "Bulk", 4) == 0 ||
                        strncmp(line, "Error", 5) == 0 ) {
                    memmove(buffer, buffer + linelen, buflen - linelen);
                    index = index - linelen;
                    continue;
                }

                /* parse the response line and add a new result item */
                add_parsed_line(info, &result, line);

                /* move the remaining data to the front of the buffer */
                memmove(buffer, buffer + linelen, buflen - linelen);
                index = index - linelen;

                outstanding--;
                if ( outstanding == 0 ) {
                    break;
                }
            }
        }
    }

    if ( whois_fd != -1 ) {
        close(whois_fd);
    }

    Log(LOG_DEBUG, "Got all responses, sending them back");

    iptrie_on_all_leaves(&result, return_asn_list, &info->fd);

    Log(LOG_DEBUG, "Tidying up after asn resolution thread");

    close(info->fd);
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