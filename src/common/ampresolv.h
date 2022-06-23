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

#ifndef _COMMON_AMPRESOLV_H
#define _COMMON_AMPRESOLV_H

#include <stdint.h>
#include <pthread.h>
#include <unbound.h>

#define MAX_DNS_NAME_LEN 255

/* max wait between checking if all DNS responses have come in: 10ms */
#define MAX_DNS_POLL_USEC 10000

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

enum amp_resolve_status {
    AMP_RESOLVE_WAITING = 0,
    AMP_RESOLVE_OK = 1,
};

/* data block for callback function when name resolution is complete */
struct amp_resolve_data {
    pthread_mutex_t *lock;
    int max;                    /* maximum number of results to return */
    int qcount;                 /* how many requests for name, shared max */
    enum amp_resolve_status status; /* have we got a good response yet? */
    struct addrinfo **addrlist; /* list to store the results in */
    uint8_t family;             /* address family that was queried */
};

/* data block used to transfer information about a query to be performed */
struct amp_resolve_query {
    uint8_t namelen;            /* length of the name string that follows */
    uint8_t count;              /* maximum number of results to return */
    uint8_t family;             /* address family to query for or AF_UNSPEC */
};

/*
 * XXX may need to rethink this, can it be reconciled with the name table
 * entry? or are they too different?
 */
struct resolve_dest {
    char *name;                 /* name to be resolved */
    struct addrinfo *addr;      /* temp store for the result of getaddrinfo */
    uint8_t count;              /* maximum count of resolved addresses to use */
    int family;                 /* family of addresses to resolve */
    struct resolve_dest *next;
};
typedef struct resolve_dest resolve_dest_t;

struct ub_ctx *amp_resolver_context_init(char *servers[], int nscount,
        char *sourcev4, char *sourcev6);
void amp_resolve_add(struct ub_ctx *ctx, struct addrinfo **res,
        pthread_mutex_t *addrlist_lock, char *name, int family, int max);
void amp_resolve_freeaddr(struct addrinfo *addrlist);
void amp_resolver_context_delete(struct ub_ctx *ctx);

struct addrinfo *amp_resolve_get_list(int fd);
int amp_resolve_add_new(int fd, resolve_dest_t *resolve);
int amp_resolve_flag_done(int fd);
int amp_resolver_connect(char *path);
#endif
