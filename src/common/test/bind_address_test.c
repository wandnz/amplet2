#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>

#include "testlib.h"

/*
 * Test binding a socket to a particular address.
 */
int main(void) {
    int sock;
    socklen_t addrlen;
    struct addrinfo *address, hints;
    struct sockaddr_storage actual;
    char *addresses[] = {
        "127.0.0.1", "127.0.0.2", "127.0.0.3", "0.0.0.0",
        "::1", "::"
    };
    int count;
    int i;
    void *addr1, *addr2;
    int length;

    count = sizeof(addresses) / sizeof(char *);
    memset(&actual, 0, sizeof(actual));
    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    for ( i = 0; i < count; i++ ) {

        /* turn our address string into a more useful addrinfo struct */
        if ( getaddrinfo(addresses[i], NULL, &hints, &address) < 0 ) {
            fprintf(stderr, "Failed to get address info: %s\n",
                    strerror(errno));
            return -1;
        }

        /* create the socket */
        if ( (sock = socket(address->ai_family, SOCK_DGRAM, 0)) < 0 ) {
            fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
            return -1;
        }

        /* try to bind to the given address */
        if ( bind_socket_to_address(sock, address) < 0 ) {
            fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
            return -1;
        }

        /* get the address that the socket is actually bound to */
        addrlen = address->ai_addrlen;
        if ( getsockname(sock, (struct sockaddr*)&actual, &addrlen) < 0 ) {
            fprintf(stderr, "Failed to get socket info: %s\n", strerror(errno));
            return -1;
        }

        /* check that the bound socket matches what we were expecting */
        assert(addrlen == address->ai_addrlen);
        assert(address->ai_family == actual.ss_family);

        switch(address->ai_family) {
            case AF_INET:
                addr1 = &((struct sockaddr_in*)address->ai_addr)->sin_addr;
                addr2 = &((struct sockaddr_in*)&actual)->sin_addr;
                length = sizeof(struct in_addr);
                break;
            case AF_INET6:
                addr1 = &((struct sockaddr_in6*)address->ai_addr)->sin6_addr;
                addr2 = &((struct sockaddr_in6*)&actual)->sin6_addr;
                length = sizeof(struct in6_addr);
                break;
            default:
                assert(0);
        };

        assert(memcmp(addr1, addr2, length) == 0);

        freeaddrinfo(address);
    }

    return 0;
}
