#include <assert.h>

#include "http.h"
#include "output.h"
#include "http.pb-c.h"
#include "dscp.h"



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
