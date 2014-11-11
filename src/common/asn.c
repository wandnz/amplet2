#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <strings.h>

#include "debug.h"
#include "asn.h"
#include "iptrie.h"

//XXX duplicated in asnsock.c
static void add_parsed_line(struct iptrie *result, char *line) {

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
    /*
    if ( info != NULL ) {
        pthread_mutex_lock(info->mutex);
        iptrie_add(info->trie, (struct sockaddr*)&addr, prefix, as);
        pthread_mutex_unlock(info->mutex);
    }
    */
}



/*
 * Send the flag to the other end of the remote socket to indicate that there
 * are no more ASNs to look up. This is done by sending a partial record with
 * the address family set to AF_UNSPEC.
 */
static int amp_asn_flag_done_local(int fd) {
    uint16_t flag = AF_UNSPEC;

    if ( send(fd, &flag, sizeof(flag), MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to send asn end flag: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Send the flag to the whois server to indicate that there are no more ASNs
 * to look up. This is done by sending the plaintext string "end\n".
 */
static int amp_asn_flag_done_direct(int fd) {
    if ( send(fd, "end\n", strlen("end\n"), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send asn end flag: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Get a list of addrinfo structs that is the result of all the queries
 * that were sent to this thread. This will block until all the queries
 * complete or time out.
 */
static struct iptrie *amp_asn_fetch_results_local(int fd,
        struct iptrie *result) {

    Log(LOG_DEBUG, "Waiting for address list");

    /* everything we read should be the result of a name lookup */
    while ( 1 ) {
        int64_t asn;
        uint16_t family;
        uint8_t prefix;
        size_t addrlen;
        struct sockaddr_storage addr;

        if ( recv(fd, &asn, sizeof(asn), 0) <= 0 ) {
            break;
        }

        if ( recv(fd, &prefix, sizeof(prefix), 0) <= 0 ) {
            break;
        }

        if ( recv(fd, &family, sizeof(family), 0) <= 0 ) {
            break;
        }

        if ( family == AF_INET ) {
            addrlen = sizeof(struct sockaddr_in);
        } else if ( family == AF_INET6 ) {
            addrlen = sizeof(struct sockaddr_in6);
        } else {
            break;
        }

        if ( recv(fd, &addr, addrlen, 0) <= 0 ) {
            break;
        }

        iptrie_add(result, (struct sockaddr *)&addr, prefix, asn);
    }

    return result;
}



/*
 * Add an ASN query across the local socket - send the address family and
 * the sockaddr struct.
 */
static int amp_asn_add_query_local(int fd, struct sockaddr *address) {
    void *addr;
    int length;

    switch ( address->sa_family ) {
        case AF_INET: addr = &((struct sockaddr_in*)address)->sin_addr;
                      length = sizeof(struct in_addr);
                      break;
        case AF_INET6: addr = &((struct sockaddr_in6*)address)->sin6_addr;
                       length = sizeof(struct in6_addr);
                       break;
        default: return -1;
    };

    if ( send(fd, &address->sa_family, sizeof(uint16_t), MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to send asn address family: %s",
                strerror(errno));
        return -1;
    }

    /* send the address to lookup the asn for */
    if ( send(fd, addr, length, MSG_NOSIGNAL) < 0 ) {
        Log(LOG_WARNING, "Failed to send asn address: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Add an ASN query across a TCP connection to the whois server - send a
 * plaintext string containing the IP address, ending with a newline.
 */
static int amp_asn_add_query_direct(int fd, struct sockaddr *address) {
    char addrstr[INET6_ADDRSTRLEN];

    /* convert to a string for the query */
    switch ( address->sa_family ) {
        case AF_INET: inet_ntop(AF_INET,
                              &((struct sockaddr_in*)address)->sin_addr,
                              addrstr, INET6_ADDRSTRLEN);
                      break;
        case AF_INET6: inet_ntop(AF_INET6,
                               &((struct sockaddr_in6*)address)->sin6_addr,
                               addrstr, INET6_ADDRSTRLEN);
                       break;
        default: return -1;
    };

    /* need a newline between addresses, null terminate too to be good */
    addrstr[strlen(addrstr) + 1] = '\0';
    addrstr[strlen(addrstr)] = '\n';

    /* write this query and go back for more */
    if ( send(fd, addrstr, strlen(addrstr), 0) < 0 ) {
        Log(LOG_WARNING, "Error writing to whois socket: %s\n",strerror(errno));
        return -1;
    }

    return 0;
}



///XXX duplicate of the main loop in asnsock.c, can plug this in?
static struct iptrie *amp_asn_fetch_results_direct(int whois_fd,
        struct iptrie *result) {

    int bytes;
    char *buffer = NULL;
    int offset;
    int buflen = 1024;//XXX define? and bigger
    char *line;
    char *lineptr = NULL;
    int linelen;

    Log(LOG_DEBUG, "Fetching ASN results (standalone)");

    /* XXX smaller than planned so it will fill while testing */
    buffer = calloc(1, buflen);
    offset = 0;

    /* read the available ASN data until we run out */
    while ( (bytes = recv(whois_fd, buffer + offset,
                    buflen - offset - 1, 0)) > 0 ) {
        offset += bytes;
        buffer[offset] = '\0';

        /*
         * Only deal with whole lines of text. Also, always call strtok_r
         * with all the parameters because we modify buffer at the end
         * of the loop.
         */
        while ( index(buffer, '\n') != NULL ) {

            line = strtok_r(buffer, "\n", &lineptr);
            linelen = strlen(line) + 1;

            /* ignore the header or any error messages */
            if ( strncmp(line, "Bulk", 4) == 0 ||
                    strncmp(line, "Error", 5) == 0 ) {
                memmove(buffer, buffer + linelen, buflen - linelen);
                offset = offset - linelen;
                buffer[offset] = '\0';
                continue;
            }

            /* parse the response line and add a new result item */
            add_parsed_line(result, line);

            /* move the remaining data to the front of the buffer */
            memmove(buffer, buffer + linelen, buflen - linelen);
            offset = offset - linelen;
            buffer[offset] = '\0';

            /* XXX do something with this, if plugging into asnsock.c */
            /*
               outstanding--;
               if ( outstanding == 0 ) {
               break;
               }
             */
        }
    }

    free(buffer);

    return result;
}



/*
 * Open a TCP connection to the Team Cymru whois server and send the options
 * that will make the output look like we expect.
 * See http://www.team-cymru.org/Services/ip-to-asn.html for details.
 */
int connect_to_whois_server(void) {
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
        freeaddrinfo(result);
        return -1;
    }

    if ( connect(fd, result->ai_addr, result->ai_addrlen) < 0 ) {
        close(fd);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    /* enable bulk input mode */
    if ( send(fd, "begin\n", strlen("begin\n"), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send header to whois server: %s",
                strerror(errno));
        close(fd);
        return -1;
    }

    /* disable column headings */
    if ( send(fd, "noheader\n", strlen("noheader\n"), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send header to whois server: %s",
                strerror(errno));
        close(fd);
        return -1;
    }

    /* don't bother getting the plaintext name for the ASN */
    if ( send(fd, "noasname\n", strlen("noasname\n"), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send header to whois server: %s",
                strerror(errno));
        close(fd);
        return -1;
    }

    /*
    if ( send(fd, "prefix\n", strlen("prefix\n"), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send header to whois server: %s",
                strerror(errno));
        return -1;
    }
    */

    return fd;
}



int amp_asn_add_query(iptrie_node_t *root, void *data) {
    int fd = *(int*)data;
    struct sockaddr_storage addr;
    socklen_t socklen;

    if ( fd < 0 ) {
        Log(LOG_WARNING, "Invalid file descriptor, not adding query");
        return -1;
    }

    socklen = sizeof(struct sockaddr_storage);

    if ( getsockname(fd, (struct sockaddr*)&addr, &socklen) < 0 ) {
        return -1;
    }

    if ( addr.ss_family == AF_UNIX ) {
        /* local socket, send the query as a sockaddr to the cache process */
        return amp_asn_add_query_local(fd, root->address);
    } else {
        /* TCP whois connection, send the query as a string to whois server */
        return amp_asn_add_query_direct(fd, root->address);
    }
}



int amp_asn_flag_done(int fd) {
    struct sockaddr_storage addr;
    socklen_t socklen;

    if ( fd < 0 ) {
        Log(LOG_WARNING, "Invalid file descriptor, not sending done flag");
        return -1;
    }

    socklen = sizeof(struct sockaddr_storage);

    if ( getsockname(fd, (struct sockaddr*)&addr, &socklen) < 0 ) {
        return -1;
    }

    if ( addr.ss_family == AF_UNIX ) {
        /* local socket, need to send a family == AF_UNSPEC */
        return amp_asn_flag_done_local(fd);
    } else {
        /* TCP whois connection, need to send the "end" flag */
        return amp_asn_flag_done_direct(fd);
    }
}



struct iptrie *amp_asn_fetch_results(int fd, struct iptrie *results) {
    struct sockaddr_storage addr;
    socklen_t socklen;

    socklen = sizeof(struct sockaddr_storage);

    if ( getsockname(fd, (struct sockaddr*)&addr, &socklen) < 0 ) {
        return results;
    }

    /* local socket, read the trie of ASN results */
    if ( addr.ss_family == AF_UNIX ) {
        return amp_asn_fetch_results_local(fd, results);
    }

    /* TCP whois connection, read all the string responses and parse them */
    return amp_asn_fetch_results_direct(fd, results);
}

