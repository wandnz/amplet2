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

#include <assert.h>
#include <stdio.h>

#include "output.h"
#include "http.pb-c.h"
#include "dscp.h"
#include "tests.h"



/*
 * Print global http test settings and statistics to stdout.
 */
static void print_global_info(Amplet2__Http__Report *report) {
    assert(report);

    printf("\n");
    printf("AMP HTTP test, url:%s\n", report->header->url);
    printf("%zu servers, %d objects, total size %dB, total duration %dms\n",
            report->n_servers, report->header->total_objects,
            report->header->total_bytes, report->header->duration);
    printf("Test options:\n");
    printf("\tkeep_alive:\t\t\t\t%d\n", report->header->persist);
    printf("\tmax_connections:\t\t\t%d\n", report->header->max_connections);
    printf("\tmax_connections_per_server:\t\t%d\n",
            report->header->max_connections_per_server);
    printf("\tmax_persistent_connections_per_server:\t%d\n",
            report->header->max_persistent_connections_per_server);
    printf("\tpipelining:\t\t\t\t%d\n", report->header->pipelining);
    printf("\tpipelining_maxrequests:\t\t\t%d\n",
            report->header->pipelining_maxrequests);
    printf("\tcaching:\t\t\t\t%d\n", report->header->caching);
    printf("\tdscp:\t\t\t\t\t%s (0x%x)\n", dscp_to_str(report->header->dscp),
            report->header->dscp);
    printf("\tuseragent:\t\t\t\t\"%s\"\n", report->header->useragent);
    printf("\tproxy:\t\t\t\t\t%s\n",
            report->header->proxy ? report->header->proxy : "none");

}



/*
 * Print statistics for a single object to stdout.
 */
static void print_object(Amplet2__Http__Object *object) {
    assert(object);

    /* original object stats */
    printf("  OBJECT %s (%d) pipe=%d dns=%.6f c=%.6f p=%.6f t=%.6f "
            "s=%.6f f=%.6f bytes=%d connects=%d",
            object->path, object->code, object->pipeline, object->lookup,
            object->connect, object->start_transfer, object->total_time,
            object->start, object->end, object->size, object->connect_count);

    /* further information on caching for medialab */
    if ( object->cache_headers ) {
        printf(" cacheflags=(");
        if ( object->cache_headers->pub ) {
            printf(" pub");
        }
        if ( object->cache_headers->priv ) {
            printf(" priv");
        }
        if ( object->cache_headers->no_cache ) {
            printf(" no-cache");
        }
        if ( object->cache_headers->no_store ) {
            printf(" no-store");
        }
        if ( object->cache_headers->no_transform ) {
            printf(" no-transform");
        }
        if ( object->cache_headers->must_revalidate ) {
            printf(" must-revalidate");
        }
        if ( object->cache_headers->proxy_revalidate ) {
            printf(" proxy-revalidate");
        }
        if ( object->cache_headers->has_max_age ) {
            printf(" max-age:%d", object->cache_headers->max_age);
        }
        if ( object->cache_headers->has_s_maxage ) {
            printf(" s-maxage:%d", object->cache_headers->s_maxage);
        }
        if ( object->cache_headers->has_x_cache ) {
            printf(" x-cache:%d", object->cache_headers->x_cache);
        }
        if ( object->cache_headers->has_x_cache_lookup ) {
            printf(" x-cache-lookup:%d", object->cache_headers->x_cache_lookup);
        }
    }
    printf(" )\n");
}



/*
 * Print statistics for a single server and all the objects fetched from it.
 */
static void print_server(Amplet2__Http__Server *server) {
    unsigned int i;

    assert(server);

    printf("\n");
    printf("SERVER %s (%s) s=%.6f f=%.6f obj=%zu bytes=%u\n",
            server->hostname, server->address,
            server->start, server->end,
            server->n_objects, server->total_bytes);

    /* per-object information for this server */
    for ( i = 0; i < server->n_objects; i++ ) {
        print_object(server->objects[i]);
    }
}



/*
 * Print all the http test results.
 */
void print_http(amp_test_result_t *result) {
    Amplet2__Http__Report *msg;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__http__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print header options */
    print_global_info(msg);

    /* print each of the servers */
    for ( i = 0; i < msg->n_servers; i++ ) {
        print_server(msg->servers[i]);
    }
    printf("\n");

    amplet2__http__report__free_unpacked(msg, NULL);
}
