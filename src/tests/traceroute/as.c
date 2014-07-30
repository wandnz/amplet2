#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "global.h"
#include "testlib.h"
#include "debug.h"
#include "as.h"
#include "ampresolv.h"
#include "traceroute.h"



static int is_rfc1918(struct sockaddr *addr) {
    struct sockaddr_in block;
    block.sin_family = AF_INET;

    /* a null pointer is not an RFC1918 address */
    if ( addr == NULL ) {
        return 0;
    }

    block.sin_addr.s_addr = htonl(0x0a000000); /* 10.0.0.0/8 */
    if ( compare_addresses(addr, (struct sockaddr*)&block, 8) == 0 ) {
        return 1;
    }

    block.sin_addr.s_addr = htonl(0xac100000); /* 172.16.0.0/12 */
    if ( compare_addresses(addr, (struct sockaddr*)&block, 12) == 0 ) {
        return 1;
    }

    block.sin_addr.s_addr = htonl(0xc0a80000); /* 192.168.0.0/24 */
    if ( compare_addresses(addr, (struct sockaddr*)&block, 16) == 0 ) {
        return 1;
    }

    /* TODO add any comparable IPv6 addresses we know we can skip? */

    return 0;
}



/*
 * The Team Cymru DNS lookup requires the address to be reversed before
 * prepending it to a special zone. IPv4 addresses should have the octets
 * reversed, IPv6 addresses should have the nibbles reversed.
 */
static char *reverse_address(char *buffer, const struct sockaddr *addr) {
    assert(buffer);
    assert(addr);

    switch ( addr->sa_family ) {
        case AF_INET: {
            /* reverse the /24 */
            uint8_t ipv4[4];
            memcpy(ipv4, &((struct sockaddr_in*)addr)->sin_addr, sizeof(ipv4));
            snprintf(buffer,
                    INET6_ADDRSTRLEN + strlen(INET_AS_MAP_ZONE) + 2,
                    "0.%d.%d.%d.%s", ipv4[2], ipv4[1], ipv4[0],
                    INET_AS_MAP_ZONE);
        } break;

        case AF_INET6: {
            /* reverse the /64 */
            struct in6_addr *ipv6 = &((struct sockaddr_in6*)addr)->sin6_addr;
            /*
             * INET6_ADDRSTRLEN isn't exactly accurate here, but is longer
             * that what is required. Normally 4 characters each in 8
             * divisions, we have 1 character each in 16 divisions here.
             */
            snprintf(buffer,
                    INET6_ADDRSTRLEN + strlen(INET6_AS_MAP_ZONE) + 2,
                    "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%s",
                    ipv6->s6_addr[7] & 0x0f, (ipv6->s6_addr[7] & 0xf0) >> 4,
                    ipv6->s6_addr[6] & 0x0f, (ipv6->s6_addr[6] & 0xf0) >> 4,
                    ipv6->s6_addr[5] & 0x0f, (ipv6->s6_addr[5] & 0xf0) >> 4,
                    ipv6->s6_addr[4] & 0x0f, (ipv6->s6_addr[4] & 0xf0) >> 4,
                    ipv6->s6_addr[3] & 0x0f, (ipv6->s6_addr[3] & 0xf0) >> 4,
                    ipv6->s6_addr[2] & 0x0f, (ipv6->s6_addr[2] & 0xf0) >> 4,
                    ipv6->s6_addr[1] & 0x0f, (ipv6->s6_addr[1] & 0xf0) >> 4,
                    ipv6->s6_addr[0] & 0x0f, (ipv6->s6_addr[0] & 0xf0) >> 4,
                    INET6_AS_MAP_ZONE);
        } break;

        default: return NULL;
    };

    Log(LOG_DEBUG, "reversed: %s\n", buffer);

    return buffer;
}



/*
 * Search the list of prefixes and AS numbers for one that matches the given
 * address.
 */
static uint32_t find_as_number(struct addrinfo *list, struct sockaddr *addr) {
    struct addrinfo *rp;
    uint32_t netmask;

    for ( rp=list; rp != NULL; rp=rp->ai_next ) {
        netmask = ((struct sockaddr_in*)rp->ai_addr)->sin_port;
        if ( compare_addresses(rp->ai_addr, addr, netmask) == 0 ) {
            return rp->ai_protocol;
        }
    }

    return 0;
}



/*
 *
 */
int set_as_numbers(struct stopset_t *stopset, struct dest_info_t *donelist) {
    char buffer[INET6_ADDRSTRLEN + strlen(INET6_AS_MAP_ZONE) + 2];
    pthread_mutex_t addrlist_lock;
    int remaining = 0;
    struct addrinfo *addrlist = NULL;
    struct sockaddr *prev = NULL;
    int masklen;
    struct stopset_t *stop;
    struct dest_info_t *item;
    int i;
    int resolver_fd;

    /* connect to the local amp resolver/cache if it is available */
    if ( (resolver_fd = amp_resolver_connect(vars.nssock)) < 0 ) {
        Log(LOG_DEBUG, "No central amplet resolver, using standalone");
        pthread_mutex_init(&addrlist_lock, NULL);
    }

    /* add the items in the stopset, so they are probably only done once */
    /* XXX checking previous item only helps prevent some duplicates */
    for ( stop = stopset; stop != NULL; stop = stop->next ) {
        if ( stop->addr ) {

            /* don't lookup AS numbers for RFC1918 addresses */
            if ( is_rfc1918(stop->addr) ) {
                continue;
            }

            /* just check /24s and /64s */
            if ( stop->addr->sa_family == AF_INET ) {
                masklen = 24;
            } else {
                masklen = 64;
            }
            if ( prev == NULL ||
                    compare_addresses(prev, stop->addr, masklen) != 0 ) {
                reverse_address(buffer, stop->addr);
                if ( resolver_fd < 0 ) {
                    amp_resolve_add(vars.ctx, &addrlist, &addrlist_lock,
                            buffer, AF_TEXT, -1, &remaining);
                } else {
                    resolve_dest_t resolve;
                    resolve.family = AF_TEXT;
                    resolve.name = buffer;
                    resolve.count = -1;
                    resolve.next = (stop->next) ? (resolve_dest_t*)1 : 0;
                    amp_resolve_add_new(resolver_fd, &resolve);
                }
            }
            prev = stop->addr;
        }
    }

    /* XXX checking previous item only helps prevent some duplicates */
    for ( item = donelist; item != NULL; item = item->next ) {
        /* just check /24s and /64s */
        if ( item->addr->ai_family == AF_INET ) {
            masklen = 24;
        } else {
            masklen = 64;
        }
        for ( i = INITIAL_TTL; i < item->path_length; i++ ) {
            /* don't lookup AS numbers for RFC1918 addresses */
            if ( is_rfc1918(item->hop[i].addr->ai_addr) ) {
                continue;
            }

            if ( item->hop[i].addr ) {
                if ( prev == NULL ||
                        compare_addresses(prev, item->hop[i].addr->ai_addr,
                            masklen) != 0 ) {
                    reverse_address(buffer, item->hop[i].addr->ai_addr);
                    if ( resolver_fd < 0 ) {
                        amp_resolve_add(vars.ctx, &addrlist, &addrlist_lock,
                                buffer, AF_TEXT, -1, &remaining);
                    } else {
                        resolve_dest_t resolve;
                        resolve.family = AF_TEXT;
                        resolve.name = buffer;
                        resolve.count = -1;
                        resolve.next = (stop->next) ? (resolve_dest_t*)1 : 0;
                        amp_resolve_add_new(resolver_fd, &resolve);
                    }
                }
                prev = item->hop[i].addr->ai_addr;
            }
        }
    }

    /* wait for all the responses to come in */
    if ( resolver_fd < 0 ) {
        amp_resolve_wait(vars.ctx, &addrlist_lock, &remaining);
    } else {
        addrlist = amp_resolve_get_list(resolver_fd);
    }

    /* match up the AS numbers to the IP addresses */
    for ( item = donelist; item != NULL; item = item->next ) {
        for ( i = 0; i < item->path_length; i++ ) {
            if ( item->hop[i].addr ) {
                item->hop[i].as =
                    find_as_number(addrlist, item->hop[i].addr->ai_addr);
            }
        }
    }

    amp_resolve_freeaddr(addrlist);

    return 0;
}
