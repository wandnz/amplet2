#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "debug.h"
#include "asn.h"


/*
 *
 */
int amp_asn_flag_done(int fd) {
    uint16_t flag = AF_UNSPEC;

    /* send the supporting metadata about name length, family etc */
    if ( send(fd, &flag, sizeof(flag), 0) < 0 ) {
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
struct addrinfo *amp_asn_get_list(int fd) {
    struct addrinfo *addrlist = NULL;
    struct addrinfo item;
    uint8_t more;

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
        tmp->ai_canonname = NULL;

        assert(tmp->ai_addrlen > 0);
        assert(tmp->ai_addr);

        if ( recv(fd, tmp->ai_addr, tmp->ai_addrlen, 0) <= 0 ) {
            free(tmp);
            break;
        }

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



/*
 *
 */
int amp_asn_add_query(int fd, struct sockaddr *address) {
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

    if ( send(fd, &address->sa_family, sizeof(uint16_t), 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send asn address family: %s",
                strerror(errno));
        return -1;
    }

    /* send the address to lookup the asn for */
    if ( send(fd, addr, length, 0) < 0 ) {
        Log(LOG_WARNING, "Failed to send asn address: %s", strerror(errno));
        return -1;
    }

    return 0;
}



