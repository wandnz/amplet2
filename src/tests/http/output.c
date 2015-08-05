#include <inttypes.h>
#include <assert.h>
#include "http.h"
#include "output.h"
#include "http.pb-c.h"



/*
 *
 */
static void print_global_info(Amplet2__Http__Header *header) {
    assert(header);

    printf("\n");
    printf("AMP HTTP test, url:%s\n", header->url);
    printf("%d servers, %d objects, total size %dB, total duration %dms\n",
            header->total_servers, header->total_objects,
            header->total_bytes, header->duration);
    printf("Test options:\n");
    printf("\tkeep_alive:\t\t\t\t%d\n", header->persist);
    printf("\tmax_connections:\t\t\t%d\n", header->max_connections);
    printf("\tmax_connections_per_server:\t\t%d\n",
            header->max_connections_per_server);
    printf("\tmax_persistent_connections_per_server:\t%d\n",
            header->max_persistent_connections_per_server);
    printf("\tpipelining:\t\t\t\t%d\n", header->pipelining);
    printf("\tpipelining_maxrequests:\t\t\t%d\n",
            header->pipelining_maxrequests);
    printf("\tcaching:\t\t\t\t%d\n", header->caching);
}



/*
 *
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
    printf(" cacheflags=(");
    if ( object->pub ) {
        printf(" pub");
    }
    if ( object->priv ) {
        printf(" priv");
    }
    if ( object->no_cache ) {
        printf(" no-cache");
    }
    if ( object->no_store ) {
        printf(" no-store");
    }
    if ( object->no_transform ) {
        printf(" no-transform");
    }
    if ( object->must_revalidate ) {
        printf(" must-revalidate");
    }
    if ( object->proxy_revalidate ) {
        printf(" proxy-revalidate");
    }
    if ( object->has_max_age ) {
        printf(" max-age:%d", object->max_age);
    }
    if ( object->has_s_maxage ) {
        printf(" s-maxage:%d", object->s_maxage);
    }
    if ( object->has_x_cache ) {
        printf(" x-cache:%d", object->x_cache);
    }
    if ( object->has_x_cache_lookup ) {
        printf(" x-cache-lookup:%d", object->x_cache_lookup);
    }
    printf(" )\n");
}



/*
 *
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
 *
 */
void print_http(void *data, uint32_t len) {
    Amplet2__Http__Report *msg;
    unsigned int i;

    assert(data != NULL);

    /* unpack all the data */
    msg = amplet2__http__report__unpack(NULL, len, data);

    assert(msg);
    assert(msg->header);

    /* print header options */
    print_global_info(msg->header);

    /* print each of the servers */
    for ( i = 0; i < msg->n_servers; i++ ) {
        print_server(msg->servers[i]);
    }
    printf("\n");

    amplet2__http__report__free_unpacked(msg, NULL);
}
