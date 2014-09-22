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

#include "asnsock.h"
#include "ampresolv.h"
#include "debug.h"



/*
 * Open a TCP connection to the Team Cymru whois server and send the options
 * that will make the output look like we expect.
 */
static int connect_to_whois_server(void) {
    struct addrinfo hints, *result;
    int fd;
    char *server = "whois.cymru.com";
    char *port = "43";

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if ( getaddrinfo(server, port, &hints, &result) < 0 ) {
        return -1;
    }

    if ( (fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
        return -1;
    }

    if ( connect(fd, result->ai_addr, result->ai_addrlen) < 0 ) {
        return -1;
    }

    freeaddrinfo(result);

    //TODO check sending works ok
    send(fd, "begin\n", strlen("begin\n"), 0);
    send(fd, "noheader\n", strlen("noheader\n"), 0);
    send(fd, "noasname\n", strlen("noasname\n"), 0);
    send(fd, "prefix\n", strlen("prefix\n"), 0);

    return fd;
}



//XXX this is all duplicated in common/ampresolv.c
/*
 * convert the text result into a struct addrinfo
 */
static struct addrinfo *build_addrinfo(char *line) {
    char *asptr, *addrptr, *addr;
    struct addrinfo *item = calloc(1, sizeof(struct addrinfo));
    item->ai_addr = calloc(1, sizeof(struct sockaddr_storage));

    /* the ASN is the first part of the line */
    item->ai_protocol = atoi(strtok_r(line, "|", &asptr));

    /*
     * the address portion is next, because we are forcing all cached values
     * to be /24s or /64s, this is what we are going to use instead
     * of the actual network prefix
     */
    addr = strtok_r(NULL, "|", &asptr);
    /* trim the whitespace from front and back */
    addr = strtok_r(addr, " ", &addrptr);

    /*
     * Try to convert the address string into a sockaddr to determine the
     * address family. Build a struct addrinfo for the address portion, and
     * store the prefix length in the port field.
     */
    if ( inet_pton(AF_INET, addr,
                &((struct sockaddr_in*)item->ai_addr)->sin_addr) ) {
        item->ai_family = AF_INET;
        item->ai_addr->sa_family = AF_INET;
        item->ai_addrlen = sizeof(struct sockaddr_in);
        ((struct sockaddr_in*)item->ai_addr)->sin_port = 24;

    } else if ( inet_pton(AF_INET6, addr,
                &((struct sockaddr_in6*)item->ai_addr)->sin6_addr)) {
        item->ai_family = AF_INET6;
        item->ai_addr->sa_family = AF_INET6;
        item->ai_addrlen = sizeof(struct sockaddr_in6);
        ((struct sockaddr_in6*)item->ai_addr)->sin6_port = 64;

    } else {
        assert(0);
    }

    item->ai_canonname = NULL;
    item->ai_next = NULL;

    return item;
}



static void *amp_asn_worker_thread(void *thread_data) {
    struct amp_asn_info *info = (struct amp_asn_info*)thread_data;
    struct addrinfo *addrlist = NULL, *item;
    char addrstr[INET6_ADDRSTRLEN + 1];
    uint8_t more;
    int bytes;

    fd_set readset, writeset;
    int whois_fd = -1;
    int max_fd;
    int ready;
    int last_bulk = 0;
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

    pthread_mutex_lock(info->mutex);
    if ( time(NULL) > *info->refresh ) {
        Log(LOG_DEBUG, "Clearing ASN cache");
        iptrie_clear(*info->trie);
        *info->trie = NULL;
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
            if ( (asn = iptrie_lookup_as(*info->trie,
                            (struct sockaddr*)&addr)) > 0 ) {
                struct addrinfo *item = calloc(1, sizeof(struct addrinfo));

                pthread_mutex_unlock(info->mutex);

                /*
                 * It's in the cache, build a nice addrinfo around it,
                 * assuming that everything we put into the cache is a
                 * /24 or /64.
                 */
                item->ai_family = addr.ss_family;
                item->ai_protocol = asn;
                if ( addr.ss_family == AF_INET ) {
                    item->ai_addr = malloc(sizeof(struct sockaddr_in));
                    memcpy(item->ai_addr, &addr, sizeof(struct sockaddr_in));
                    item->ai_addrlen = sizeof(struct sockaddr_in);
                    ((struct sockaddr_in*)item->ai_addr)->sin_port = 24;
                } else {
                    item->ai_addr = malloc(sizeof(struct sockaddr_in6));
                    memcpy(item->ai_addr, &addr, sizeof(struct sockaddr_in6));
                    item->ai_addrlen = sizeof(struct sockaddr_in6);
                    ((struct sockaddr_in6*)item->ai_addr)->sin6_port = 64;
                }

                item->ai_canonname = NULL;
                item->ai_next = addrlist;
                addrlist = item;
                continue;
            }
            pthread_mutex_unlock(info->mutex);

            /* convert to a string for the query */
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
            struct addrinfo *item;
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

                item = build_addrinfo(line);
                item->ai_next = addrlist;
                addrlist = item;

                /* move the remaining data to the front of the buffer */
                memmove(buffer, buffer + linelen, buflen - linelen);
                index = index - linelen;

                pthread_mutex_lock(info->mutex);
                if ( item->ai_family == AF_INET ) {
                    *info->trie = iptrie_add(*info->trie, item->ai_addr,
                            ((struct sockaddr_in*)item->ai_addr)->sin_port,
                            item->ai_protocol);
                } else {
                    *info->trie = iptrie_add(*info->trie, item->ai_addr,
                            ((struct sockaddr_in6*)item->ai_addr)->sin6_port,
                            item->ai_protocol);
                }
                pthread_mutex_unlock(info->mutex);

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

    /* send back all the results of name resolution */
    for ( item = addrlist; item != NULL; item = item->ai_next) {
        if ( send(info->fd, item, sizeof(*item), MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send resolved address info: %s",
                    strerror(errno));
            goto end;
        }

        if ( send(info->fd, item->ai_addr, item->ai_addrlen,
                    MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send resolved address: %s",
                    strerror(errno));
            goto end;
        }

        more = (item->ai_next) ? 1 : 0;
        if ( send(info->fd, &more, sizeof(uint8_t), MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send more flag: %s", strerror(errno));
            goto end;
        }
    }

    Log(LOG_DEBUG, "asn resolution thread completed, exiting");

end:
    close(info->fd);
    amp_resolve_freeaddr(addrlist);
    free(thread_data);
    free(buffer);

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
