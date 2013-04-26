#include <inttypes.h>
#include "http.h"
#include "output.h"



static void dump_opts(struct opt_t *opt) {
    printf("----------------------------------------\n");
    printf("OPTIONS:\n");
    printf("URL:\t\t\t\t\t%s\n", opt->url);
    printf("keep_alive:\t\t\t\t%d\n", opt->keep_alive);
    printf("max_connections:\t\t\t%d\n", opt->max_connections);
    printf("max_connections_per_server:\t\t%d\n",
            opt->max_connections_per_server);
    printf("max_persistent_connections_per_server:\t%d\n",
            opt->max_persistent_connections_per_server);
    printf("pipelining:\t\t\t\t%d\n", opt->pipelining);
    printf("pipelining_maxrequests:\t\t\t%d\n",
            opt->pipelining_maxrequests);
}



static void dump_object_queue(struct object_stats_t *queue) {
    if ( queue == NULL ) {
        return;
    }

    /* original object stats */
    printf("\tOBJECT %s (%ld) pipe=%d dns=%f c=%f p=%f t=%f s=%d.%.6d "
            "f=%d.%.6d bytes=%d connects=%ld",
            queue->path, queue->code, queue->pipeline, queue->lookup,
            queue->connect, queue->start_transfer, queue->total_time,
            (int)queue->start.tv_sec, (int)queue->start.tv_usec,
            (int)queue->end.tv_sec, (int)queue->end.tv_usec,
            queue->size, queue->connect_count);

    /* further information on caching for medialab */
    printf(" cacheflags=%" PRIu8, *((uint8_t*)&queue->headers.flags));
    printf(" max-age=%d s-maxage=%d x-cache=%d x-cache-lookup=%d",
            queue->headers.max_age, queue->headers.s_maxage,
            queue->headers.x_cache, queue->headers.x_cache_lookup);

    printf("\n");

    dump_object_queue(queue->next);
}



static void dump_server_list(struct server_stats_t *servers) {
    int i;

    if(servers == NULL)
        return;

    printf("SERVER %s (%s) s=%d.%.6d f=%d.%.6d obj=%d bytes=%d\n",
            servers->server_name, servers->address,
            (int)servers->start.tv_sec, (int)servers->start.tv_usec,
            (int)servers->end.tv_sec, (int)servers->end.tv_usec,
            servers->objects, servers->bytes);

    dump_object_queue(servers->finished);

    /* XXX while testing, dump all objects that haven't completed */
    if(servers->pending != NULL) {
        printf("\n-----------PENDING--------------\n");
        dump_object_queue(servers->pending);
        printf("\n++++++++++++++++++\n");
    }

    for(i=0; i < servers->num_pipelines; i++) {
        if(servers->pipelines[i] != NULL) {
            printf("\n-----------IN PROGRESS %d--------------\n", i);
            dump_object_queue(servers->pipelines[i]);
            printf("\n++++++++++++++++++\n");
        }
    }

    dump_server_list(servers->next);
}


void output_full_stats(struct server_stats_t *servers, struct opt_t* options) {
    dump_opts(options);
    dump_server_list(servers);
}
