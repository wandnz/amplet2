#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "http.h"
#include "http.pb-c.h"

#define MAX_TIME 30.0

/* these are globals as we need to get them into the print callback */
int option_count = 0;
struct opt_t options[] = {
    {{"http://example.org"},{0},{0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {{"http://example.com"},{0},{0}, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0},
    {{"http://wand.net.nz"},{0},{0}, 1, 24, 8, 2, 1, 4, 1, 0, 0, 0, 0, 0, 0},
};


struct server_stats_t *servers = NULL;

/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Http__Header *b) {
    assert(strcmp(a->url, b->url) == 0);

    assert(b->has_duration);
    assert(((global.end.tv_sec-global.start.tv_sec) * 1000) +
        (global.end.tv_usec-global.start.tv_usec + 500) / 1000 == b->duration);

    assert(b->has_total_bytes);
    assert(global.bytes == b->total_bytes);
    assert(b->has_total_objects);
    assert(global.objects == b->total_objects);

    assert(b->has_max_connections);
    assert((uint32_t)a->max_connections == b->max_connections);
    assert(b->has_max_connections_per_server);
    assert((uint32_t)a->max_connections_per_server ==
            b->max_connections_per_server);
    assert(b->has_pipelining_maxrequests);
    assert((uint32_t)a->pipelining_maxrequests == b->pipelining_maxrequests);
    assert(b->has_max_persistent_connections_per_server);
    assert((uint32_t)a->max_persistent_connections_per_server ==
            b->max_persistent_connections_per_server);
    assert(b->has_persist);
    assert(a->keep_alive == b->persist);
    assert(b->has_pipelining);
    assert(a->pipelining == b->pipelining);
    assert(b->has_caching);
    assert(a->caching == b->caching);
}



#if 0
/*
 *
 */
static void verify_server(struct server_stats_t *a, Amplet2__Http__Server *b) {
    assert(strcmp(a->server_name, b->hostname) == 0);
    assert(b->has_start);
    assert((double)a->start.tv_sec + ((double)a->start.tv_usec / 1000000.0) ==
            b->start);
    assert(b->has_end);
    assert((double)a->end.tv_sec + ((double)a->end.tv_usec / 1000000.0) ==
            b->end);
    assert(strcmp(a->address, b->address) == 0);
    assert(b->has_total_bytes);
    assert(a->bytes == b->total_bytes);
    //repeated Object objects = 7;
}
#endif



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(void *data, uint32_t len) {
    Amplet2__Http__Report *msg;
    //struct server_stats_t *tmpsrv;
    //unsigned int i;

    assert(data);

    /* unpack all the data */
    msg = amplet2__http__report__unpack(NULL, len, data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_servers == global.servers);

    verify_header(&options[option_count++], msg->header);

#if 0
    /* check each of the servers in the result */
    for ( i = 0, tmpsrv = servers; i < msg->n_servers && tmpsrv != NULL;
            i++, tmpsrv = tmpsrv->next ) {
        verify_server(tmpsrv, msg->servers[i]);
    }

    assert(tmpsrv == NULL);
    assert(i == msg->n_servers);
#endif
    amplet2__http__report__free_unpacked(msg, NULL);
}



#if 0
/*
 *
 */
static object_stats_t* build_object(object_stats_t *list) {
    struct object_stats_t *object;

    object = (struct object_stats_t*)calloc(1, sizeof(struct object_stats_t));
    strncpy(object->path, path);
    object->start = start;
    object->end = end;
    object->lookup = lookup;
    object->connect = connect;
    object->start_transfer = start_transfer;
    object->total_time = total_time;
    object->code = code;
    object->size = size;
    object->connect_count = connect_count;
    object->pipeline = pipeline;
    object->next = list;
    //XXX headers
    global.objects++;
    global.bytes += bytes;

    object->lookup = ((float)rand()/(float)(RAND_MAX)) * MAX_TIME;
}



/*
 *
 */
static void build_server(char *name, char *address, struct timeval start,
        struct timeval end, uint32_t bytes, uint32_t objects,
        uint32_t fobjects) {

    int i;
    struct server_stats_t *server;

    server = (struct server_stats_t*)calloc(1, sizeof(struct server_stats_t));
    strcpy(server->server_name, name);
    strcpy(server->address, address);
    server->start = start;
    server->end = end;
    server->bytes = bytes;
    server->objects = objects;
    server->failed_objects = fobjects;
    server->next = servers;
    servers = server;

    global.servers++;

    for ( i = 0; i < objects; i++ ) {
        server->finished = build_object(server->finished);
    }
}
#endif



/*
 *
 */
int main(void) {
    test_t http_test;
    int count, i;
    struct timeval start = {1, 0};
    //struct timeval end = {2, 12345};

    /* set the test not to report, so it will call the print function */
    http_test.report = 0;
    /* replace the print function with one that will verify message contents */
    http_test.print_callback = verify_message;
    /* use this stripped down test in place of the normal ICMP test */
    amp_tests[AMP_TEST_HTTP] = &http_test;

    memset(&global, 0, sizeof(struct globalStats_t));

#if 0
    build_server("", "", start, end, 0, 0, 0);
    build_server("foo", "", start, end, 1000, 1, 0);
#endif

    count = sizeof(options) / sizeof(struct opt_t);
    for ( i = 0; i < count; i++ ) {
        amp_test_report_results(&start, servers, &options[i]);
    }

    return 0;
}
