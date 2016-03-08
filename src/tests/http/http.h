#ifndef _TESTS_HTTP_H
#define _TESTS_HTTP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "tests.h"
#include "curl/curl.h"

/* use the current date with 2 digit count appended as version: YYYYMMDDXX */
#define AMP_HTTP_TEST_VERSION 2015030400

#define MAX_DNS_NAME_LEN 256
#define MAX_PATH_LEN 2048
#define MAX_ADDR_LEN 46

#define MAX_URL_LEN (MAX_PATH_LEN + MAX_DNS_NAME_LEN)


/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    char url[MAX_URL_LEN];
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];
    int keep_alive;                            /* persistent connections? */
    int max_connections;                        /* maximum total connections */
    int max_connections_per_server;             /* per server max connections */
    int max_persistent_connections_per_server;  /* per server max persist con */
    int pipelining;                            /* use pipelining? */
    int pipelining_maxrequests;                 /* max outstanding requests */
    int caching;                               /* allow cached content */
    int parse;                                  /* extract objects from page */
    int pipe_size_before_skip;
    char *device;                               /* source device name */
    char *sourcev4;                             /* source v4 address */
    char *sourcev6;                             /* source v6 address */
    long sslversion;                            /* SSL version to use */
    uint8_t dscp;
};

struct cache_headers_t {
    int32_t max_age;
    int32_t s_maxage;
    char reserved[5];
    int8_t x_cache;
    int8_t x_cache_lookup;
    struct cache_flags_t{
        uint8_t pub:1;
        uint8_t priv:1;
        uint8_t no_cache:1;
        uint8_t no_store:1;
        uint8_t no_transform:1;
        uint8_t must_revalidate:1;
        uint8_t proxy_revalidate:1;
        uint8_t unused:1;
    } flags;
} __attribute__((packed));

struct globalStats_t {
    struct timeval start;
    struct timeval end;
    uint32_t bytes;
    uint32_t servers;
    uint32_t objects;
    uint32_t failed_objects;
} global;//XXX move elsewhere?

/* TODO can these stats structs be reconciled with the report ones? */
struct server_stats_t {
    char server_name[MAX_DNS_NAME_LEN];
    char address[MAX_ADDR_LEN];
    struct timeval start;
    struct timeval end;
    uint32_t bytes;
    uint32_t objects;
    uint32_t failed_objects;
    uint32_t currentPipe;
    uint32_t pipelining_maxrequests;
    uint32_t *pipelen;
    int num_pipelines;
    struct object_stats_t **pipelines;
    struct object_stats_t *pending;
    struct object_stats_t *finished;
    struct server_stats_t *next;
};

struct object_stats_t {
    char server_name[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];
    char url[MAX_URL_LEN];
    struct cache_headers_t headers;
    struct curl_slist *slist;
    struct timeval start;
    struct timeval end;
    double lookup;
    double connect;
    double start_transfer;
    double total_time;
    uint32_t size;
    long connect_count;
    long code;
    CURL *handle;
    uint8_t pipeline;
    char *location;
    int parse;
    struct object_stats_t *next;
};



int run_http(int argc, char *argv[], int count, struct addrinfo **dests);
int save_http(char *monitor, uint64_t timestamp, void *data, uint32_t len);
void print_http(void *data, uint32_t len);
test_t *register_test(void);
CURL *pipeline_next_object(CURLM *multi, struct server_stats_t *server);
struct server_stats_t *add_object(char *url, int parse);


#if UNIT_TEST
void amp_test_http_split_url(char *orig_url, char *server, char *path, int set);
void amp_test_report_results(struct timeval *start_time,
        struct server_stats_t *server_stats, struct opt_t *opt);
#endif

#endif
