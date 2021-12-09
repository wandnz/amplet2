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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "http.h"
#include "servers.h"

extern int total_pipelines;



/*
 * Create a new server statistics object.
 */
static struct server_stats_t *create_server(char *name, int pipelines) {
    struct server_stats_t *server =
        (struct server_stats_t*)malloc(sizeof(struct server_stats_t));
    int i;

    memset(server, 0, sizeof(struct server_stats_t));
    snprintf(server->server_name, MAX_DNS_NAME_LEN, "%s", name);
    snprintf(server->address, MAX_ADDR_LEN, "0.0.0.0");

    server->pipelining_maxrequests = 1;
    server->pipelines = malloc(pipelines * sizeof(struct object_stats_t*));
    server->pipelen = malloc(pipelines * sizeof(int));
    server->num_pipelines = pipelines;

    for ( i = 0; i < pipelines; i++ ) {
        server->pipelines[i] = NULL;
        server->pipelen[i] = 0;
    }

    global.servers++;

    return server;
}



/*
 * Try to find the given server name in the server list. If it is not found
 * then it should be created. Regardless, the (possibly updated) server list
 * is returned and a reference to the particular server is stored in result.
 */
struct server_stats_t *get_server(char *name,
        struct server_stats_t *server, struct server_stats_t **result) {

    assert(name);
    assert(result);

    /* the server list is empty, create the server and return it as the list */
    if ( server == NULL ) {
        *result = create_server(name, total_pipelines);
        return *result;
    }

    /* this is the server we were after */
    if ( strcmp(name, server->server_name) == 0 ) {
        *result = server;
        return server;
    }

    /* keep looking down the list */
    server->next = get_server(name, server->next, result);
    return server;
}
