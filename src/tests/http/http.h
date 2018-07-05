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

#ifndef _TESTS_HTTP_H
#define _TESTS_HTTP_H

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h>
#include <curl/curl.h>
#include "tests.h"


#define MAX_DNS_NAME_LEN 256
#define MAX_PATH_LEN 2048
#define MAX_ADDR_LEN 46

#define MAX_URL_LEN (MAX_PATH_LEN + MAX_DNS_NAME_LEN + 1)


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
    int forcev4;                                /* force use of ipv4 */
    int forcev6;                                /* force use of ipv6 */
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



amp_test_result_t* run_http(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_http(amp_test_result_t *result);
test_t *register_test(void);
CURL *pipeline_next_object(CURLM *multi, struct server_stats_t *server);
struct server_stats_t *add_object(char *url, int parse);


#if UNIT_TEST
void amp_test_http_split_url(char *orig_url, char *server, char *path, int set);
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        struct server_stats_t *server_stats, struct opt_t *opt);
#endif

#endif
