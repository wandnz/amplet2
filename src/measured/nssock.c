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
#include <sys/socket.h>
#include <sys/types.h>
#include <unbound.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "nssock.h"
#include "ampresolv.h"
#include "debug.h"



/*
 * Receive all the queries from the local socket and wait for them to resolve
 * before sending them back to the test process.
 */
static void *amp_resolver_worker_thread(void *thread_data) {
    struct amp_resolve_info *data = (struct amp_resolve_info *)thread_data;
    struct addrinfo *addrlist = NULL, *item;
    char name[MAX_DNS_NAME_LEN];
    struct amp_resolve_query info;
    uint8_t more;
    uint8_t namelen;
    int bytes;
    pthread_mutex_t addrlist_lock;
    int remaining = 0;

    Log(LOG_DEBUG, "Starting new name resolution thread");

    pthread_mutex_init(&addrlist_lock, NULL);

    /* everything we read should be a name to lookup */
    while ( 1 ) {

        /* read name length, address count, family etc */
        if ( recv(data->fd, &info, sizeof(info), 0) <= 0 ) {
            Log(LOG_WARNING, "Error reading name info, aborting");
            break;
        }

        /* zero here is a marker - no more names need to be resolved */
        if ( info.namelen == 0 ) {
            break;
        }

        if ( (bytes = recv(data->fd, name, info.namelen, 0)) <= 0 ) {
            Log(LOG_WARNING, "Error reading name, aborting");
            break;
        }

        Log(LOG_DEBUG, "Read %d bytes for name '%s'", bytes, name);

        /* add it to the list of names to resolve and go back for more */
        amp_resolve_add(data->ctx, &addrlist, &addrlist_lock, name,
                info.family, info.count, &remaining);
    }

    Log(LOG_DEBUG, "Got all requests, waiting for responses");

    /* when the remote end has finished sending names, wait for resolution */
    amp_resolve_wait(data->ctx, &addrlist_lock, &remaining);

    /* once we have all the responses then we don't need the addrlist lock */
    pthread_mutex_lock(&addrlist_lock);

    Log(LOG_DEBUG, "Got all responses, sending them back");

    /* send back all the results of name resolution */
    for ( item = addrlist; item != NULL; item = item->ai_next) {
        if ( send(data->fd, item, sizeof(*item), MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send resolved address info: %s",
                    strerror(errno));
            goto end;
        }

        if ( send(data->fd, item->ai_addr,item->ai_addrlen,MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send resolved address: %s",
                    strerror(errno));
            goto end;
        }

        namelen = strlen(item->ai_canonname) + 1;
        assert(namelen > 1);
        if ( send(data->fd, &namelen, sizeof(namelen), MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send resolved canonical name: %s",
                    strerror(errno));
            goto end;
        }

        assert(item->ai_canonname);
        if ( send(data->fd, item->ai_canonname, namelen, MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send resolved canonical name: %s",
                    strerror(errno));
            goto end;
        }

        more = (item->ai_next) ? 1 : 0;
        if ( send(data->fd, &more, sizeof(uint8_t), MSG_NOSIGNAL) < 0 ) {
            Log(LOG_WARNING, "Failed to send more flag: %s", strerror(errno));
            goto end;
        }
    }

    Log(LOG_DEBUG, "Name resolution thread completed, exiting");

end:
    close(data->fd);
    amp_resolve_freeaddr(addrlist);
    pthread_mutex_unlock(&addrlist_lock);
    pthread_mutex_destroy(&addrlist_lock);
    free(data);

    pthread_exit(NULL);
}



/*
 * Delete the unbound context.
 */
void amp_resolver_context_delete(struct ub_ctx *ctx) {
    assert(ctx);
    ub_ctx_delete(ctx);
}



/*
 * Accept a new connection on the local name resolution socket and spawn
 * a new thread to deal with the queries from the test process.
 */
void resolver_socket_event_callback(
        __attribute__((unused))wand_event_handler_t *ev_hdl, int eventfd,
        void *data, __attribute__((unused))enum wand_eventtype_t ev) {

    int fd;
    pthread_t thread;
    struct amp_resolve_info *info;

    Log(LOG_DEBUG, "Accepting for new resolver connection");

    if ( (fd = accept(eventfd, NULL, NULL)) < 0 ) {
        Log(LOG_WARNING, "Failed to accept for name resolution: %s",
                strerror(errno));
        return;
    }

    Log(LOG_DEBUG, "Accepted new resolver connection on fd %d", fd);

    info = calloc(1, sizeof(struct amp_resolve_info));
    info->ctx = data;
    info->fd = fd;

    /* create the thread and detach, we don't need to look after it */
    pthread_create(&thread, NULL, amp_resolver_worker_thread, info);
    pthread_detach(thread);
}
