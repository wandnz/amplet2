#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "global.h"
#include "testlib.h"
#include "debug.h"
#include "as.h"
#include "ampresolv.h"
#include "traceroute.h"
#include "asn.h"
#include "iptrie.h"



static int is_private_address(struct sockaddr *addr) {

    /* a null pointer is not an RFC1918 address */
    if ( addr == NULL ) {
        return 0;
    }

    if ( addr->sa_family == AF_INET ) {
        struct sockaddr_in block;
        block.sin_family = AF_INET;

        block.sin_addr.s_addr = 0; /* 0.0.0.0 */
        if ( compare_addresses(addr, (struct sockaddr*)&block, 32) == 0 ) {
            return 1;
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

    } else if ( addr->sa_family == AF_INET6 ) {
        struct sockaddr_in6 block;

        block.sin6_family = AF_INET6;
        memset(&block.sin6_addr, 0, sizeof(block.sin6_addr));
        if ( compare_addresses(addr, (struct sockaddr*)&block, 128) == 0 ) {
            return 1;
        }

        /* TODO add any comparable IPv6 addresses we know we can skip? */
    }

    return 0;
}



/*
 *
 */
int set_as_numbers(struct dest_info_t *donelist) {
    struct iptrie trie = { NULL, NULL };
    struct dest_info_t *item;
    int masklen;
    int asn_fd;
    int i;

    /* connect to the local amp ASN cache if it is available */
    if ( (asn_fd = amp_resolver_connect(vars.asnsock)) < 0 ) {
        Log(LOG_DEBUG, "No central ASN resolver, using standalone");
        if ( (asn_fd = connect_to_whois_server()) < 0 ) {
            Log(LOG_DEBUG, "No ability to resolve ASNs, skipping");
            return -1;
        }
    }

    /*
     * Build a trie of all the networks we need to check. There are possibly
     * lots of duplicate /24s and /64s in the doneset, this will filter out
     * duplicates so we can make fewer queries.
     */
    for ( item = donelist; item != NULL; item = item->next ) {
        if ( item->path_length < 1 || item->first_response < 1 ) {
            continue;
        }

        /* just check /24s and /64s */
        if ( item->addr->ai_family == AF_INET ) {
            masklen = 24;
        } else {
            masklen = 64;
        }

        for ( i = 0; i < item->path_length; i++ ) {
            if ( item->hop[i].addr && item->hop[i].addr->ai_addr ) {
                /* don't lookup AS numbers for RFC1918 addresses */
                if ( is_private_address(item->hop[i].addr->ai_addr) ) {
                    continue;
                }

                iptrie_add(&trie, item->hop[i].addr->ai_addr, masklen, 0);
            }
        }
    }

    /* traverse the trie and actually make the queries now */
    iptrie_on_all_leaves(&trie, amp_asn_add_query, &asn_fd);
    amp_asn_flag_done(asn_fd);

    /* fetch all the results into the same trie we queried from, setting ASNs */
    amp_asn_fetch_results(asn_fd, &trie);

    /* match up the AS numbers to the IP addresses */
    for ( item = donelist; item != NULL; item = item->next ) {
        for ( i = 0; i < item->path_length; i++ ) {
            if ( item->hop[i].addr ) {
                if ( is_private_address(item->hop[i].addr->ai_addr) ) {
                    item->hop[i].as = AS_PRIVATE;
                } else {
                    item->hop[i].as = iptrie_lookup_as(&trie,
                            item->hop[i].addr->ai_addr);
                }
            } else {
                item->hop[i].as = AS_NULL;
            }
        }
    }

    iptrie_clear(&trie);

    return 0;
}
