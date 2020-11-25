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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include "iptrie.h"
#include "testlib.h"


/*
 * Get the bit in the address at the given zero-based index. Expects either
 * an IPv4 or IPv6 address in network byte order.
 */
static int get_bit_at_index(struct sockaddr *address, int index) {
    int offset;

    if ( address == NULL || index < 0 ) {
        return -1;
    }

    if ( address->sa_family == AF_INET ) {
        if ( index > 31 ) {
            return -1;
        }

        /* line up the one set bit with the index we want */
        offset = ntohl(0x80000000 >> index);
        return (((struct sockaddr_in*)address)->sin_addr.s_addr & offset)?1:0;

    } else if ( address->sa_family == AF_INET6 ) {
        int field;
        if ( index > 127 ) {
            return -1;
        }

        /* determine which 32bit block of the IPv6 address we need to check */
        field = index / 16;

        /* line up the one set bit with the index we want within the block */
        offset = ntohs(0x8000 >> (index % 16));
        return (((struct sockaddr_in6*)
                address)->sin6_addr.s6_addr16[field] & offset)?1:0;

    }

    return -1;
}



/*
 * Count the number of initial bits that match in a pair of addresses. Accepts
 * either IPv4 or IPv6 addresses, in network byte order.
 */
static int get_matching_prefix_length(struct sockaddr *a, struct sockaddr *b) {
    int count = 0;

    if ( a == NULL || b == NULL ) {
        return -1;
    }

    if ( a->sa_family != b->sa_family ) {
        return -1;
    }

    if ( a->sa_family == AF_INET ) {
        struct sockaddr_in *a4 = (struct sockaddr_in*)a;
        struct sockaddr_in *b4 = (struct sockaddr_in*)b;
        int mask = 0x80000000;
        int maxlen = 32;

        /* count bits that are the same, from the left, stop when different */
        while ( count < maxlen &&
                (a4->sin_addr.s_addr & ntohl(mask)) ==
                (b4->sin_addr.s_addr & ntohl(mask)) ) {
            count++;
            mask = (mask >> 1) | 0x80000000;
        }

    } else if ( a->sa_family == AF_INET6 ) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6*)a;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6*)b;
        int mask = 0x8000;
        int maxlen = 128;
        int i;

        for ( i = 0; i < 8; i++ ) {
            if ( a6->sin6_addr.s6_addr16[i] == b6->sin6_addr.s6_addr16[i] ) {
                /* skip a whole block if it's the same, don't need to count */
                count += 16;
            } else {
                /* count bits that are the same, from the left */
                while ( count < maxlen &&
                        (a6->sin6_addr.s6_addr16[i] & ntohs(mask)) ==
                        (b6->sin6_addr.s6_addr16[i] & ntohs(mask)) ) {
                    count++;
                    mask = (mask >> 1) | 0x8000;
                }
                break;
            }
        }
    }

    return count;
}



/*
 * Add or update an address with ASN in the trie. If the address does not
 * exist then it will be added at the appropriate location, if it does exist
 * then it will be updated.
 */
static iptrie_node_t *iptrie_add_internal(iptrie_node_t *root,
        struct sockaddr *address, uint8_t prefix, int64_t as) {

    int cmp, len;

    /* missing address, return the trie unchanged */
    if ( address == NULL ) {
        return root;
    }

    /* empty trie, add this address at the root */
    if ( root == NULL ) {
        iptrie_node_t *node = malloc(sizeof(iptrie_node_t));
        node->as = as;
        node->prefix = prefix;
        if ( address->sa_family == AF_INET ) {
            node->address = malloc(sizeof(struct sockaddr_in));
            memcpy(node->address, address, sizeof(struct sockaddr_in));
        } else {
            node->address = malloc(sizeof(struct sockaddr_in6));
            memcpy(node->address, address, sizeof(struct sockaddr_in6));
        }
        node->left = NULL;
        node->right = NULL;
        node->next = NULL;
        return node;
    }

    /* there is a prefix set and this address matches, update the ASN */
    if ( prefix == root->prefix &&
            compare_addresses(root->address, address, prefix) == 0 ) {
        root->as = as;
        return root;
    }


    /*
     * Prefix and address don't match, see how similar this node actually is.
     * If it matches more than the node prefix, limit it... we have more
     * nodes that we have to check below for a better match first.
     */
    if ( (len = get_matching_prefix_length(root->address, address)) >
            root->prefix ) {
        len = root->prefix;
    }

    /* get the first bit that didn't match */
    cmp = get_bit_at_index(address, len);

    /*
     * If the matching prefix length is shorter than the prefix length already
     * at this node, then we need to insert a new branching node at this
     * location. The address we are trying to add and the node currently here
     * will become children of this new branching node.
     */
    if ( len < root->prefix ) {
        iptrie_node_t *node = malloc(sizeof(iptrie_node_t));
        node->as = 0;
        node->prefix = len;
        if ( address->sa_family == AF_INET ) {
            node->address = malloc(sizeof(struct sockaddr_in));
            memcpy(node->address, address, sizeof(struct sockaddr_in));
        } else {
            node->address = malloc(sizeof(struct sockaddr_in6));
            memcpy(node->address, address, sizeof(struct sockaddr_in6));
        }
        node->left = NULL;
        node->right = NULL;
        node->next = NULL;

        if ( cmp == 0 ) {
            /* the next bit is a zero, add it down the left branch */
            node->left = iptrie_add_internal(node->left, address, prefix, as);
            /* and put the existing node on the right branch */
            node->right = root;
        } else {
            /* the next bit is a one, add it down the right branch */
            node->right = iptrie_add_internal(node->right, address, prefix, as);
            /* and put the existing node on the left branch */
            node->left = root;
        }

        return node;
    }

    /*
     * otherwise, we match the address here so far but it isn't the end,
     * keep looking down the appropriate branch for where we should insert.
     */
    if ( cmp == 0 ) {
        /* the next bit is a zero, go down the left branch */
        root->left = iptrie_add_internal(root->left, address, prefix, as);
    } else {
        /* the next bit is a one, go down the right branch */
        root->right = iptrie_add_internal(root->right, address, prefix, as);
    }

    return root;
}



/*
 * We keep separate tries for ipv4 and ipv6, so figure out which one we should
 * use based on the address we've been given to add.
 */
void iptrie_add(struct iptrie *root, struct sockaddr *address,
        uint8_t prefix, int64_t as) {

    switch ( address->sa_family ) {
        case AF_INET:
            root->ipv4 = iptrie_add_internal(root->ipv4, address, prefix, as);
            break;
        case AF_INET6:
            root->ipv6 = iptrie_add_internal(root->ipv6, address, prefix, as);
            break;
    };
}



/*
 *
 */
static int64_t iptrie_lookup_as_internal(iptrie_node_t *root,
        struct sockaddr *address) {
    int next;

    /* empty trie or missing address, can't return a useful AS number */
    if ( root == NULL || address == NULL ) {
        return -1;
    }

    /* if the address doesn't match at this prefix, it isn't present */
    if ( compare_addresses(root->address, address, root->prefix) != 0 ) {
        return -1;
    }

    /* if this is a leaf node, then it matches what we were looking for */
    if ( root->left == NULL && root->right == NULL ) {
        return root->as;
    }

    /* compare the next bit in the address to see which branch we should take */
    next = get_bit_at_index(address, root->prefix);

    /* non-leaf node, continue down the trie and try the next branch */
    if ( next == 0 && root->left ) {
        return iptrie_lookup_as_internal(root->left, address);
    } else if ( next == 1 && root->right ) {
        return iptrie_lookup_as_internal(root->right, address);
    }

    /* no branch where expected, the ASN isn't here */
    return -1;
}



/*
 * We keep separate tries for ipv4 and ipv6, so figure out which one we should
 * use based on the address we've been given to look up.
 */
int64_t iptrie_lookup_as(struct iptrie *root, struct sockaddr *address) {

    switch ( address->sa_family ) {
        case AF_INET:
            return iptrie_lookup_as_internal(root->ipv4, address);
        case AF_INET6:
            return iptrie_lookup_as_internal(root->ipv6, address);
    };

    return -1;
}



/*
 * Post-order traversal, free each node after freeing all the children.
 */
static void iptrie_clear_internal(iptrie_node_t *root) {
    if ( root == NULL ) {
        return;
    }

    iptrie_clear_internal(root->left);
    iptrie_clear_internal(root->right);

    free(root->address);
    free(root);
}



void iptrie_clear(struct iptrie *root) {
    iptrie_clear_internal(root->ipv4);
    iptrie_clear_internal(root->ipv6);

    root->ipv4 = NULL;
    root->ipv6 = NULL;
}



/*
 * Apply the user function to each of the leaves (only the leaves contain
 * values that were added, internal nodes have been created as a by-product).
 */
static int iptrie_on_all_leaves_internal(iptrie_node_t *root,
        int (*func)(iptrie_node_t *node, void *data), void *data) {

    if ( root == NULL ) {
        return 0;
    }

    if ( root->left == NULL && root->right == NULL ) {
        return func(root, data);
    } else {
        if ( iptrie_on_all_leaves_internal(root->left, func, data) < 0 ) {
            return -1;
        }
        if ( iptrie_on_all_leaves_internal(root->right, func, data) < 0 ) {
            return -1;
        }
    }

    return 0;
}



/*
 * Apply the user function to each of the leaves (only the leaves contain
 * values that were added, internal nodes have been created as a by-product).
 */
int iptrie_on_all_leaves(struct iptrie *root,
        int (*func)(iptrie_node_t*, void*), void *data) {

    if ( iptrie_on_all_leaves_internal(root->ipv4, func, data) < 0 ) {
        return -1;
    }

    if ( iptrie_on_all_leaves_internal(root->ipv6, func, data) < 0 ) {
        return -1;
    }

    return 0;
}



/*
 * Traverse the trie and join all the leaves together into a list.
 */
static int iptrie_to_list_internal(iptrie_node_t *node, void *data) {

    if ( node == NULL ) {
        return 0;
    }

    node->next = *((iptrie_node_t**)data);
    *((iptrie_node_t**)data) = node;

    return 0;
}



/*
 * Traverse the trie and join all the leaves together into a list.
 */
iplist_t *iptrie_to_list(struct iptrie *root) {
    iplist_t *list = NULL;
    iptrie_on_all_leaves(root, iptrie_to_list_internal, &list);
    return list;
}



/*
 * Check if the trie is empty and has no entries.
 */
int iptrie_is_empty(struct iptrie *root) {
    if ( root->ipv4 == NULL && root->ipv6 == NULL ) {
        return 1;
    }

    return 0;
}
