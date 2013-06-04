#include <inttypes.h>
#include <assert.h>
#include "http.h"
#include "output.h"



static void print_global_info(struct http_report_header_t *header) {
    assert(header);

    printf("\n");
    printf("AMP HTTP test, url:%s\n", header->url);
    printf("%d servers, %d objects, total size %dB, total duration %dms\n",
            header->total_servers, header->total_objects,
            header->bytes, header->duration);
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



static void print_object(struct http_report_object_t *object) {
    assert(object);

    /* original object stats */
    printf("  OBJECT %s (%d) pipe=%d dns=%" PRIu64 ".%.6" PRIu64
            " c=%" PRIu64 ".%.6" PRIu64 " p=%" PRIu64 ".%.6" PRIu64
            " t=%" PRIu64 ".%.6" PRIu64 " s=%" PRIu64 ".%.6" PRIu64
            " f=%" PRIu64 ".%.6" PRIu64 " bytes=%d connects=%d",
            object->path, object->code, object->pipeline, object->lookup.tv_sec,
            object->lookup.tv_usec, object->connect.tv_sec,
            object->connect.tv_usec, object->start_transfer.tv_sec,
            object->start_transfer.tv_usec, object->total_time.tv_sec,
            object->total_time.tv_usec,
            object->start.tv_sec, object->start.tv_usec,
            object->end.tv_sec, object->end.tv_usec,
            object->size, object->connect_count);

    /* further information on caching for medialab */
    printf(" cacheflags=%" PRIu8, *((uint8_t*)&object->headers.flags));
    printf(" max-age=%d s-maxage=%d x-cache=%d x-cache-lookup=%d",
            object->headers.max_age, object->headers.s_maxage,
            object->headers.x_cache, object->headers.x_cache_lookup);

    printf("\n");
}



static int print_server(struct http_report_server_t *server) {
    struct http_report_object_t *object;
    int i;

    assert(server);

    printf("\n");
    printf("SERVER %s (%s) s=%d.%.6d f=%d.%.6d obj=%d bytes=%d\n",
            server->hostname, server->address,
            (int)server->start.tv_sec, (int)server->start.tv_usec,
            (int)server->end.tv_sec, (int)server->end.tv_usec,
            server->objects, server->bytes);

    /* per-object information for this server */
    for ( i = 0; i < server->objects; i++ ) {
        object = (struct http_report_object_t *)(((char *)server) +
                sizeof(struct http_report_server_t) +
                (i * sizeof(struct http_report_object_t)));
        print_object(object);
    }

    return server->objects;
}



void print_http(void *data, uint32_t len) {
    struct http_report_header_t *header = (struct http_report_header_t*)data;
    struct http_report_server_t *server;
    int reported_objects = 0;
    int i;

    assert(data != NULL);
    assert(len >= sizeof(struct http_report_header_t));
    assert(header->version == AMP_HTTP_TEST_VERSION);

    /* print header options */
    print_global_info(header);

    for ( i=0; i<header->total_servers; i++ ) {
        /* specific server information */
        server = (struct http_report_server_t*)(data +
                sizeof(struct http_report_header_t) +
                i * sizeof(struct http_report_server_t) +
                reported_objects * sizeof(struct http_report_object_t));
        reported_objects += print_server(server);
    }
    printf("\n");

}
