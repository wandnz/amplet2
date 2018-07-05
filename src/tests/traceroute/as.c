/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "global.h"
#include "debug.h"
#include "as.h"
#include "ampresolv.h"
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
    Log(LOG_DEBUG, "Building address trie to check ASNs");
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
    Log(LOG_DEBUG, "Sending all addresses for ASN resolution");
    if ( iptrie_on_all_leaves(&trie, amp_asn_add_query, &asn_fd) < 0 ) {
        goto end;
    }

    Log(LOG_DEBUG, "Done sending all addresses for ASN resolution");
    if ( amp_asn_flag_done(asn_fd) < 0 ) {
        goto end;
    }

    /* fetch all the results into the same trie we queried from, setting ASNs */
    Log(LOG_DEBUG, "Fetching results of ASN resolution");
    if ( amp_asn_fetch_results(asn_fd, &trie) == NULL ) {
        goto end;
    }

    /* match up the AS numbers to the IP addresses */
    Log(LOG_DEBUG, "Matching results of ASN resolution with addresses");
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

end:
    close(asn_fd);
    iptrie_clear(&trie);

    return 0;
}
