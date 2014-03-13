#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "tests.h"
#include "traceroute.h"

#define MAXLEN 9000
#define ID_COUNT (sizeof(ids) / sizeof(int))
#define TTL_COUNT (sizeof(ttls) / sizeof(int))
#define IDENT_COUNT (sizeof(idents) / sizeof(uint16_t))
#define SIZE_COUNT (sizeof(packet_sizes) / sizeof(int))

/*
 * Check that the body of the IPv6 packet is built correctly. We rely on
 * the operating system to construct the rest of the packet for us (IPv6/UDP
 * headers etc).
 */
static void check_ipv6_probe(void *packet, int id, uint16_t ident,
        struct addrinfo *dest) {

    struct ipv6_body_t *ipv6_body;

    ipv6_body = (struct ipv6_body_t *)packet;
    assert(ntohs(ipv6_body->index) == id);
    assert(ntohs(ipv6_body->ident) == ident);
    assert(ntohs(((struct sockaddr_in6 *)dest->ai_addr)->sin6_port) ==
            TRACEROUTE_DEST_PORT);
}

/*
 * Check that the traceroute test builds sane IPv6 probe packets.
 */
int main(void) {
    char packet[MAXLEN];
    uint16_t id, ttl, size, ident, coded_id;
    struct addrinfo addr;
    int length;

    /* id is incremented by one for every destination site */
    int ids[] = {0, 1, 2, 3, 4, 8, 16, 32};

    /* ttl is incremented by one until destination responds */
    int ttls[] = {1, 2, 3, 4, 8, 16, MAX_HOPS_IN_PATH};

    /* all idents should be from 9001 to 65535 */
    uint16_t idents[] = {9001, 11111, 12345, 33333, 65535};

    /* packet size is usually default, but it can be changed */
    int packet_sizes[] = {
        MIN_TRACEROUTE_PROBE_LEN,
        DEFAULT_TRACEROUTE_PROBE_LEN,
        256,
        512,
        1024,
        1472,
        MAXLEN,
    };

    /* make sure we have some storage for our fake address */
    memset(&addr, 0, sizeof(addr));
    addr.ai_addr = (struct sockaddr *)malloc(sizeof(struct sockaddr_in6));
    addr.ai_family = AF_INET6;
    addr.ai_addrlen = sizeof(struct sockaddr_in6);
    addr.ai_canonname = NULL;
    addr.ai_next = NULL;

    /* lets try every combination of values, there aren't that many */
    for ( id = 0; id < ID_COUNT; id++ ) {
        for ( ttl = 0; ttl < TTL_COUNT; ttl++ ) {
            for ( ident = 0; ident < IDENT_COUNT; ident++ ) {
                for ( size = 0; size < SIZE_COUNT; size++ ) {

                    /* actual id in packet also includes ttl */
                    coded_id = (ttls[ttl] << 10) + ids[id];

                    /* construct the probe packet */
                    length = amp_traceroute_build_ipv6_probe(packet,
                            packet_sizes[size], coded_id, idents[ident], &addr);

                    /* check the constructed probe packet */
                    assert(length == packet_sizes[size]);
                    check_ipv6_probe(packet, coded_id, idents[ident], &addr);
                }
            }
        }
    }

    free(addr.ai_addr);

    return 0;
}
