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

#ifndef _COMMON_IPTRIE_H
#define _COMMON_IPTRIE_H

#include <stdint.h>
#include <netinet/in.h>


#define iptrie_node_t struct iptrie_node
#define iplist_t struct iptrie_node
struct iptrie_node {
    /* ASNs are only 32bit, but we can use the extra space as markers */
    int64_t as;
    uint8_t prefix;
    struct sockaddr *address;

    iptrie_node_t *left;
    iptrie_node_t *right;
    iptrie_node_t *next;
};

struct iptrie {
    iptrie_node_t *ipv4;
    iptrie_node_t *ipv6;
};



void iptrie_add(struct iptrie *root, struct sockaddr *address,
        uint8_t prefix, int64_t as);
int64_t iptrie_lookup_as(struct iptrie *root, struct sockaddr *address);
void iptrie_clear(struct iptrie *root);
int iptrie_on_all_leaves(struct iptrie *root,
        int (*func)(iptrie_node_t*, void*), void *data);
iplist_t *iptrie_to_list(struct iptrie *root);
int iptrie_is_empty(struct iptrie *root);
#endif
