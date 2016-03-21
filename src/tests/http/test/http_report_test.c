#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <math.h>

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "http.h"
#include "http.pb-c.h"

#define MAX_TIME 30
#define MAX_BYTES (1024 * 1024 * 10)
#define MAX_OBJECTS 256
#define MAX_SERVERS 32
#define MAX_CONNECTS 3
#define MAX_HOST_PARTS 10
#define MAX_HOST_PART_LEN 63
#define MAX_PATH_PARTS 20
#define MAX_PATH_PART_LEN 127
#define EPSILON 0.000001

/* these are globals as we need to get them into the print callback */
int option_count = 0;
struct server_stats_t *servers = NULL;
struct opt_t options[] = {
    {{"http://example.org"},
        {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {{"http://example.com/"},
        {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8},
    {{"http://foo.bar.baz.example.org"},
        {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10},
    {{"http://foo.bar.baz.wand.net.nz/a/b/c/d/e.fgh"},
        {0}, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12},

    {{"http://example.org"},
        {0}, {0}, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 16},
    {{"http://example.com/"},
        {0}, {0}, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 20},
    {{"http://foo.bar.baz.example.org"},
        {0}, {0}, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 24},
    {{"http://foo.bar.baz.wand.net.nz/a/b/c/d/e.fgh"},
        {0}, {0}, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 26},

    {{"http://example.org"},
        {0}, {0}, 1, 24, 8, 2, 1, 4, 1, 0, 0, 0, 0, 0, 0, 28},
    {{"http://example.com/"},
        {0}, {0}, 1, 24, 8, 2, 1, 4, 1, 0, 0, 0, 0, 0, 0, 30},
    {{"http://foo.bar.baz.example.org"},
        {0}, {0}, 1, 24, 8, 2, 1, 4, 1, 0, 0, 0, 0, 0, 0, 34},
    {{"http://foo.bar.baz.wand.net.nz/a/b/c/d/e.fgh"},
        {0}, {0}, 1, 24, 8, 2, 1, 4, 1, 0, 0, 0, 0, 0, 0, 36},

    {{"http://example.org"},
        {0}, {0}, 1, 512, 256, 128, 1, 64, 1, 0, 0, 0, 0, 0, 0, 46},
    {{"http://example.com/"},
        {0}, {0}, 1, 1024, 512, 256, 1, 128, 1, 0, 0, 0, 0, 0, 0, 48},
    {{"http://foo.bar.baz.example.org"},
        {0}, {0}, 1, 2048, 1024, 512, 1, 256, 1, 0, 0, 0, 0, 0, 0, 56},
    {{"http://foo.bar.baz.wand.net.nz/a/b/c/d/e.fgh"},
        {0}, {0}, 1, 2147483647, 2147483647, 2147483647, 1, 2147483647,
        1, 0, 0, 0, 0, 0, 0, 63},
};



/*
 * Check if two floating point values are close enough to be considered the
 * same value. In our case we are only checking start/end times that are at
 * timeval precision but are converted into doubles to transmit on the network.
 */
static int is_almost_equal(double a, double b) {
    return fabs(a - b) < EPSILON;
}



/*
 * Return a string containing a random IPv4 or IPv6 address.
 */
static void build_random_address(char *address) {
    if ( rand() % 2 ) {
        struct in_addr addr;
        addr.s_addr = rand() % (1<<31);
        inet_ntop(AF_INET, &addr, address, INET6_ADDRSTRLEN);
    } else {
        struct in6_addr addr6;
        addr6.s6_addr32[0] = rand() % (1<<31);
        addr6.s6_addr32[1] = rand() % (1<<31);
        addr6.s6_addr32[2] = rand() % (1<<31);
        addr6.s6_addr32[3] = rand() % (1<<31);
        inet_ntop(AF_INET6, &addr6, address, INET6_ADDRSTRLEN);
    }
}



/*
 * Return a random string made up of printable characters.
 */
static char* build_random_string(int maxlen) {
    int i;
    int length = rand() % (maxlen - 1);
    char *string = (char *)calloc(1, length + 1);

    for ( i = 0; i < length; i++ ) {
        /* limit it to ascii 32 -> 126 */
        string[i] = (rand() % 95) + 32;
    }

    return string;
}



/*
 * Return a random fully qualified domain name, including URI scheme.
 */
static void build_random_host(char *hostname) {
    int i;
    int maxparts;
    char *part = NULL;

    maxparts = rand() % MAX_HOST_PARTS;

    switch ( rand() % 2 ) {
        case 0: strcat(hostname, "http://"); break;
        case 1: strcat(hostname, "https://"); break;
    };

    for ( i = 0; i < maxparts &&
            strlen(hostname) < MAX_DNS_NAME_LEN - MAX_HOST_PART_LEN; i++ ) {
        if ( i != 0 ) {
            strcat(hostname, ".");
        }
        part = build_random_string(MAX_HOST_PART_LEN);
        strcat(hostname, part);
        free(part);
    }
}



/*
 * Return a random URL path
 */
static void build_random_path(char *path) {
    int i;
    int maxparts;
    char *part = NULL;

    maxparts = rand() % MAX_PATH_PARTS;

    for ( i = 0; i < maxparts &&
            strlen(path) < MAX_PATH_LEN - MAX_PATH_PART_LEN; i++ ) {
        if ( i != 0 ) {
            strcat(path, "/");
        }
        part = build_random_string(MAX_PATH_PART_LEN);
        strcat(path, part);
        free(part);
    }

    /* 2/3 of the time append a random 3 character extension if there is room */
    if ( (rand() % 3) && strlen(path) < (MAX_PATH_LEN - 5) ) {
        part = build_random_string(3);
        strcat(path, ".");
        strcat(path, part);
        free(part);
    }
}



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



/*
 * Check that the protocol buffer object has the same values as the options
 * the test tried to report.
 */
static void verify_object(struct object_stats_t *a, Amplet2__Http__Object *b) {
    assert(strcmp(a->path, b->path) == 0);
    assert(b->has_start);
    assert(is_almost_equal(
                (double)a->start.tv_sec + ((double)a->start.tv_usec/1000000.0),
                b->start));
    assert(b->has_end);
    assert(is_almost_equal(
                (double)a->end.tv_sec + ((double)a->end.tv_usec / 1000000.0),
                b->end));

    assert(b->has_lookup);
    assert(a->lookup == b->lookup);
    assert(b->has_connect);
    assert(a->connect == b->connect);
    assert(b->has_start_transfer);
    assert(a->start_transfer == b->start_transfer);
    assert(b->has_total_time);
    assert(a->total_time == b->total_time);
    assert(b->has_code);
    assert(a->code == b->code);
    assert(b->has_size);
    assert(a->size == b->size);
    assert(b->has_connect_count);
    assert(a->connect_count == b->connect_count);
    assert(b->has_pipeline);
    assert(a->pipeline == b->pipeline);

    assert(b->cache_headers);
    if ( a->headers.max_age != -1 ) {
        assert(b->cache_headers->has_max_age);
        assert(a->headers.max_age == b->cache_headers->max_age);
    } else {
        assert(!b->cache_headers->has_max_age);
    }

    if ( a->headers.s_maxage != -1 ) {
        assert(b->cache_headers->has_s_maxage);
        assert(a->headers.s_maxage == b->cache_headers->s_maxage);
    } else {
        assert(!b->cache_headers->has_s_maxage);
    }

    if ( a->headers.x_cache != -1 ) {
        assert(b->cache_headers->has_x_cache);
        assert(a->headers.x_cache == b->cache_headers->x_cache);
    } else {
        assert(!b->cache_headers->has_x_cache);
    }

    if ( a->headers.x_cache_lookup != -1 ) {
        assert(b->cache_headers->has_x_cache_lookup);
        assert(a->headers.x_cache_lookup == b->cache_headers->x_cache_lookup);
    } else {
        assert(!b->cache_headers->has_x_cache_lookup);
    }

    assert(b->cache_headers->has_pub);
    assert(a->headers.flags.pub == b->cache_headers->pub);
    assert(b->cache_headers->has_priv);
    assert(a->headers.flags.priv == b->cache_headers->priv);
    assert(b->cache_headers->has_no_cache);
    assert(a->headers.flags.no_cache == b->cache_headers->no_cache);
    assert(b->cache_headers->has_no_store);
    assert(a->headers.flags.no_store == b->cache_headers->no_store);
    assert(b->cache_headers->has_no_transform);
    assert(a->headers.flags.no_transform == b->cache_headers->no_transform);
    assert(b->cache_headers->has_must_revalidate);
    assert(a->headers.flags.must_revalidate ==
            b->cache_headers->must_revalidate);
    assert(b->cache_headers->has_proxy_revalidate);
    assert(a->headers.flags.proxy_revalidate ==
            b->cache_headers->proxy_revalidate);
}



/*
 * Check that the protocol buffer server has the same values as the options
 * the test tried to report.
 */
static void verify_server(struct server_stats_t *a, Amplet2__Http__Server *b) {
    struct object_stats_t *object;
    unsigned int i;

    assert(strcmp(a->server_name, b->hostname) == 0);
    assert(b->has_start);
    assert(is_almost_equal(
                (double)a->start.tv_sec + ((double)a->start.tv_usec/1000000.0),
                b->start));
    assert(b->has_end);
    assert(is_almost_equal(
                (double)a->end.tv_sec + ((double)a->end.tv_usec / 1000000.0),
                b->end));
    assert(strcmp(a->address, b->address) == 0);
    assert(b->has_total_bytes);
    assert(a->bytes == b->total_bytes);

    for ( i = 0, object = a->finished; i < b->n_objects && object != NULL;
            i++, object = object->next ) {
        verify_object(object, b->objects[i]);
    }

    assert(object == NULL);
    assert(i == b->n_objects);
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Http__Report *msg;
    struct server_stats_t *tmpsrv;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__http__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_servers == global.servers);

    verify_header(&options[option_count++], msg->header);

    /* check each of the servers in the result */
    for ( i = 0, tmpsrv = servers; i < msg->n_servers && tmpsrv != NULL;
            i++, tmpsrv = tmpsrv->next ) {
        verify_server(tmpsrv, msg->servers[i]);
    }

    assert(tmpsrv == NULL);
    assert(i == msg->n_servers);

    amplet2__http__report__free_unpacked(msg, NULL);
}



/*
 *
 */
static struct object_stats_t* build_object(struct object_stats_t *list) {
    struct object_stats_t *object;

    object = (struct object_stats_t*)calloc(1, sizeof(struct object_stats_t));

    build_random_path((char*)&object->path);

    gettimeofday(&object->start, NULL);
    object->end.tv_sec = object->start.tv_sec + (rand() % MAX_TIME);
    object->end.tv_usec = (rand() % 1000000);

    object->lookup = ((float)rand()/(float)(RAND_MAX)) * MAX_TIME;
    object->connect = ((float)rand()/(float)(RAND_MAX)) * MAX_TIME;
    object->start_transfer = ((float)rand()/(float)(RAND_MAX)) * MAX_TIME;
    object->total_time = ((float)rand()/(float)(RAND_MAX)) * MAX_TIME;
    object->code = (rand() % 406) + 100;
    object->size = rand() % MAX_BYTES;
    object->connect_count = rand() % MAX_CONNECTS;
    object->pipeline = rand() % (MAX_SERVERS * 8);

    object->headers.max_age = (rand() % 2) ? (rand() % (1<<30)) : -1;
    object->headers.s_maxage = (rand() % 2) ? (rand() % (1<<30)) : -1;
    object->headers.x_cache = rand() % 2;
    object->headers.x_cache_lookup = rand() % 2;

    object->headers.flags.pub = rand() % 2;
    object->headers.flags.priv = rand() % 2;
    object->headers.flags.no_cache = rand() % 2;
    object->headers.flags.no_store = rand() % 2;
    object->headers.flags.no_transform = rand() % 2;
    object->headers.flags.must_revalidate = rand() % 2;
    object->headers.flags.proxy_revalidate = rand() % 2;

    object->next = list;

    global.objects++;
    global.bytes += object->size;

    return object;
}



/*
 *
 */
static void build_server(void) {

    unsigned int i;
    struct server_stats_t *server;

    server = (struct server_stats_t*)calloc(1, sizeof(struct server_stats_t));

    build_random_host((char*)&server->server_name);
    build_random_address((char*)&server->address);

    gettimeofday(&server->start, NULL);
    server->end.tv_sec = server->start.tv_sec + (rand() % MAX_TIME);
    server->end.tv_usec = (rand() % 1000000);
    server->bytes = rand() % MAX_BYTES;
    server->objects = rand() % MAX_OBJECTS;
    server->failed_objects = rand() % MAX_OBJECTS;
    server->next = servers;
    servers = server;

    global.servers++;

    for ( i = 0; i < server->objects + server->failed_objects; i++ ) {
        server->finished = build_object(server->finished);
    }
}



/*
 *
 */
static void build_servers(void) {
    int i;
    int count = rand() % MAX_SERVERS;

    for ( i = 0; i < count; i++ ) {
        build_server();
    }
}



/*
 *
 */
static void free_objects(struct object_stats_t *objects) {
    struct object_stats_t *object, *tmp;

    for ( object = objects; object != NULL; /* nothing */ ) {
        tmp = object;
        object = object->next;
        free(tmp);
    }
}



/*
 *
 */
static void free_servers(void) {
    struct server_stats_t *server, *tmp;

    for ( server = servers; server != NULL; /* nothing */) {
        tmp = server;
        server = server->next;
        free_objects(tmp->finished);
        free(tmp);
    }

    servers = NULL;
    global.servers = 0;
    global.objects = 0;
}



/*
 * Throw a bunch of random data through the report functions to make sure that
 * it comes out correctly on the other side.
 */
int main(void) {
    test_t http_test;
    int count, i;
    struct timeval start = {1, 0};

    /* do we want a fixed seed to be able to reproduce problems? */
    //srand(time(NULL));
    srand(1);

    /* replace the print function with one that will verify message contents */
    http_test.print_callback = verify_message;
    /* use this stripped down test in place of the normal HTTP test */
    amp_tests[AMP_TEST_HTTP] = &http_test;

    memset(&global, 0, sizeof(struct globalStats_t));

    count = sizeof(options) / sizeof(struct opt_t);
    for ( i = 0; i < count; i++ ) {
        build_servers();
        amp_test_report_results(&start, servers, &options[i]);
        free_servers();
    }

    return 0;
}
