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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <curl/curl.h>

#if _WIN32
#define exit(status) exit_test(status)
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "config.h"
#include "testlib.h"
#include "http.h"
#include "servers.h"
#include "parsers.h"
#include "output.h"
#include "http.pb-c.h"
#include "debug.h"
#include "usage.h"
#include "dscp.h"


CURLM *multi;
CURLSH *share_handle = NULL;
struct server_stats_t *server_list = NULL;
int total_pipelines;
int total_requests;
struct opt_t options;



static struct option long_options[] = {
    {"user-agent", required_argument, 0, 'a'},
    {"useragent", required_argument, 0, 'a'},
    {"cached", no_argument, 0, 'c'},
    {"dontparse", no_argument, 0, 'd'},
    {"no-keep-alive", no_argument, 0, 'k'},
    {"max-con", required_argument, 0, 'm'},
    {"max-persistent-con-per-server", required_argument, 0, 'o'},
    {"max-persistent-con", required_argument, 0, 'o'},
    {"max-persistent", required_argument, 0, 'o'},
    {"pipeline", no_argument, 0, 'p'},
    {"proxy", required_argument, 0, 'P'},
    {"max-pipelined-requests", required_argument, 0, 'r'},
    {"max-pipelined", required_argument, 0, 'r'},
    {"max-con-per-server", required_argument, 0, 's'},
    {"max-per-server", required_argument, 0, 's'},
    {"sslversion", required_argument, 0, 'S'},
    {"url", required_argument, 0, 'u'},
    {"pipe-size", required_argument, 0, 'z'},
    {"dscp", required_argument, 0, 'Q'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", optional_argument, 0, '4'},
    {"ipv6", optional_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {NULL, 0, 0, 0}
};



/*
 * Fill in the standard report header with options that were set
 */
static void report_header_results(Amplet2__Http__Header *header,
        struct opt_t *opt) {

    assert(header);
    assert(opt);

    header->url = opt->url;
    header->has_duration = 1;
    header->duration = ((global.end.tv_sec - global.start.tv_sec) * 1000) +
        (global.end.tv_usec - global.start.tv_usec + 500) / 1000;
    header->has_total_bytes = 1;
    header->total_bytes = global.bytes;
    header->has_total_objects = 1;
    header->total_objects = global.objects + global.failed_objects;

    header->has_max_connections = 1;
    header->max_connections = opt->max_connections;
    header->has_max_connections_per_server = 1;
    header->max_connections_per_server = opt->max_connections_per_server;
    header->has_pipelining_maxrequests = 1;
    header->pipelining_maxrequests = opt->pipelining_maxrequests;
    header->has_max_persistent_connections_per_server = 1;
    header->max_persistent_connections_per_server =
        opt->max_persistent_connections_per_server;

    header->has_persist = 1;
    header->persist = opt->keep_alive;
    header->has_pipelining = 1;
    header->pipelining = opt->pipelining;
    header->has_caching = 1;
    header->caching = opt->caching;
    header->has_dscp = 1;
    header->dscp = opt->dscp;
    header->useragent = opt->useragent;
    /* TODO consider sanitising usernames and passwords used for the proxy */
    header->proxy = opt->proxy;
}



/*
 * Construct a protocol buffer message containing the cache headers present
 * in the HTTP response.
 */
static Amplet2__Http__CacheHeaders* report_cache_headers(
        struct cache_headers_t *cache) {

    Amplet2__Http__CacheHeaders *headers = (Amplet2__Http__CacheHeaders*)
        malloc(sizeof(Amplet2__Http__CacheHeaders));

    amplet2__http__cache_headers__init(headers);

    if ( cache->max_age != -1 ) {
        headers->has_max_age = 1;
        headers->max_age = cache->max_age;
    }

    if ( cache->s_maxage != -1 ) {
        headers->has_s_maxage = 1;
        headers->s_maxage = cache->s_maxage;
    }

    if ( cache->x_cache != -1 ) {
        headers->has_x_cache = 1;
        headers->x_cache = cache->x_cache;
    }

    if ( cache->x_cache_lookup != -1 ) {
        headers->has_x_cache_lookup = 1;
        headers->x_cache_lookup = cache->x_cache_lookup;
    }

    /* these are all enabled when present, so are disabled if missing */
    headers->has_pub = 1;
    headers->pub = cache->flags.pub;
    headers->has_priv = 1;
    headers->priv = cache->flags.priv;
    headers->has_no_cache = 1;
    headers->no_cache = cache->flags.no_cache;
    headers->has_no_store = 1;
    headers->no_store = cache->flags.no_store;
    headers->has_no_transform = 1;
    headers->no_transform = cache->flags.no_transform;
    headers->has_must_revalidate = 1;
    headers->must_revalidate = cache->flags.must_revalidate;
    headers->has_proxy_revalidate = 1;
    headers->proxy_revalidate = cache->flags.proxy_revalidate;

    return headers;
}



/*
 * Report on a single object.
 */
static Amplet2__Http__Object* report_object_results(
        struct object_stats_t *info) {

    Amplet2__Http__Object *object =
        (Amplet2__Http__Object*)malloc(sizeof(Amplet2__Http__Object));

    assert(object);
    assert(info);

    amplet2__http__object__init(object);

    /* total time should always exist, convert from timeval to float */
    object->has_start = 1;
    object->start = (double)info->start.tv_sec +
        ((double)info->start.tv_usec / 1000000.0);
    object->has_end = 1;
    object->end = (double)info->end.tv_sec +
        ((double)info->end.tv_usec / 1000000.0);

    /* split timings should always exist */
    object->has_lookup = 1;
    object->lookup = info->lookup;
    object->has_connect = 1;
    object->connect = info->connect;
    object->has_start_transfer = 1;
    object->start_transfer = info->start_transfer;
    object->has_total_time = 1;
    object->total_time = info->total_time;

    /* XXX some objects have code 0 and failed somehow... */
    object->has_code = 1;
    object->code = info->code;
    object->has_size = 1;
    object->size = info->size;
    object->has_connect_count = 1;
    object->connect_count = info->connect_count;
    object->has_pipeline = 1;
    object->pipeline = info->pipeline;
    object->path = info->path;
    object->cache_headers = report_cache_headers(&info->headers);

    return object;
}



/*
 * Report on a single server and all objects that were fetched from it.
 */
static Amplet2__Http__Server* report_server_results(
        struct server_stats_t *info) {

    unsigned int i;
    struct object_stats_t *object_info;
    Amplet2__Http__Server *server =
        (Amplet2__Http__Server*)malloc(sizeof(Amplet2__Http__Server));

    assert(info);
    assert(server);

    /* fill the report item with results of a test */
    amplet2__http__server__init(server);
    server->hostname = info->server_name;
    server->address = info->address;

    server->has_start = 1;
    server->start = (double)info->start.tv_sec +
        ((double)info->start.tv_usec / 1000000.0);
    server->has_end = 1;
    server->end = (double)info->end.tv_sec +
        ((double)info->end.tv_usec / 1000000.0);

    server->has_total_bytes = 1;
    server->total_bytes = info->bytes;
    server->n_objects = info->objects + info->failed_objects;

    /* deal with all the objects fetched from this server */
    server->objects = malloc(
            sizeof(Amplet2__Http__Object*) * server->n_objects);

    for ( i = 0, object_info = info->finished;
            i < server->n_objects && object_info != NULL;
            i++, object_info = object_info->next ) {

        Log(LOG_DEBUG, "Reporting object %d of %d\n", i+1, server->n_objects);
        server->objects[i] = report_object_results(object_info);
    }

    return server;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for each server/object.
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        struct server_stats_t *server_stats, struct opt_t *opt) {

    unsigned int i, j;
    struct server_stats_t *tmpsrv;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Amplet2__Http__Report msg = AMPLET2__HTTP__REPORT__INIT;
    Amplet2__Http__Header header = AMPLET2__HTTP__HEADER__INIT;
    Amplet2__Http__Server **servers;

    Log(LOG_DEBUG, "Building http report, url:%s\n", opt->url);

    report_header_results(&header, opt);

    /* add results for all the servers from which data was fetched */
    servers = malloc(sizeof(Amplet2__Http__Server*) * global.servers);
    for ( i = 0, tmpsrv = server_stats;
            i < global.servers && tmpsrv != NULL; i++, tmpsrv = tmpsrv->next ) {
        Log(LOG_DEBUG, "Reporting server %d of %d: %s\n", i+1, global.servers,
                tmpsrv->address);
        servers[i] = report_server_results(tmpsrv);
    }

    /* populate the top level report object with the header and servers */
    msg.header = &header;
    msg.servers = servers;
    msg.n_servers = global.servers;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__http__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__http__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < global.servers; i++ ) {
        for ( j = 0; j < servers[i]->n_objects; j++ ) {
            if ( servers[i]->objects[j]->cache_headers ) {
                free(servers[i]->objects[j]->cache_headers);
            }
            free(servers[i]->objects[j]);
        }
        free(servers[i]->objects);
        free(servers[i]);
    }

    free(servers);

    return result;
}



/*
 * Split URL into server and path components. Based on code originally from
 * the first HTTP test in AMP.
 */
static void split_url(char *orig_url, char *server, char *path, int set) {
    static char *base_server = NULL;
    static char *base_path = NULL;
    static char *base_scheme = NULL;
    char *scheme;
    char *start;
    char *end;
    char *url;
    int length;

    assert(orig_url);
    assert(server);
    assert(path);

    url = orig_url;

    /* check initial protocol portion, currently only understand http/https */
    if ( strncasecmp(url, "http://", 7) == 0 ) {
        /* full url, treat as normal */
        start = url + 7;
        scheme = "http";
    } else if ( strncasecmp(url, "https://", 8) == 0 ) {
        /* full url, treat as normal */
        start = url + 8;
        scheme = "https";
    } else if ( strncasecmp(url, "//", 2) == 0 ) {
        /*
         * 2 slashes means it's a remote URL accessed over the same protocol
         * as the current document.
         */
        scheme = base_scheme ? base_scheme : "http";
        if ( asprintf(&url, "%s://%s", scheme, orig_url + 2) < 0 ) {
            Log(LOG_WARNING, "Failed to build full URL for %s", orig_url);
            exit(EXIT_FAILURE);
        }
        start = url + strlen(scheme) + 3;
    } else if ( strncasecmp(url, "/", 1) == 0 ) {
        /* one slash makes this an absolute path on the current host */
        assert(base_server);
        strncpy(server, base_server, MAX_DNS_NAME_LEN);
        strncpy(path, url, MAX_PATH_LEN);
        return;
    } else if ( base_server != NULL && base_path != NULL ) {
        /* no initial slashes but not the first url, treat as a relative path */
        char *slash = strrchr(base_path, '/');
        strncpy(server, base_server, MAX_DNS_NAME_LEN);
        memset(path, 0, MAX_PATH_LEN);
        strncpy(path, base_path, (slash - base_path) + 1);
        /*
         * This is really naive, but try to fix any urls that start by going
         * up the directory tree past the root. Doesn't even try to deal with
         * any that do this somewhere in the middle of the url. If a url tries
         * to go too far up the tree, the browser appears to clamp at the root.
         * TODO be less naive, deal with stupidity in the middle of urls
         */
        if ( strstr(url, "../") == url ) {
            /* last slash in the path */
            slash = strrchr(path, '/');
            /* while the url starts with "../", keep stripping it */
            while ( strstr(url, "../") == url ) {
                Log(LOG_DEBUG,
                        "Poorly formed directory traversal, trying to fix");
                /* strip one level of the path if there are still any left */
                if ( slash != path ) {
                    *slash = '\0';
                    slash = strrchr(path, '/');
                    *(slash+1) = '\0';
                }
                /* advance one level of the url */
                url += 3;
            }
        }
        strncat(path, url, MAX_PATH_LEN - strlen(base_path) - 1);
        return;
    } else {
        /* initial url, treat it as http */
        scheme = "http";
        if ( asprintf(&url, "%s://%s", scheme, orig_url) < 0 ) {
            Log(LOG_WARNING, "Failed to build full URL for %s", orig_url);
            exit(EXIT_FAILURE);
        }
        start = url + strlen(scheme) + 3;
    }

    /* determine end of the host portion and extract the remaining path */
    if ( (end = strchr(start, '/')) == NULL ) {
        if ( (end = strchr(start, '?')) == NULL ) {
            /* no '?' or '/', make the path just a '/' */
            end = start + strlen(start);
            strncpy(path, "/\0", 2);
        } else {
            /* no '/' but there is a '?', split on that instead */
            snprintf(path, MAX_PATH_LEN, "/%s", end);
        }
    } else {
        /* split on the first '/' */
        strncpy(path, end, MAX_PATH_LEN);
        path[MAX_PATH_LEN - 1] = '\0';
    }

    /* save the host portion also */
    length = end - url;
    assert(length < MAX_DNS_NAME_LEN);
    strncpy(server, url, length);
    server[length] = '\0';

    /* save these so we can later parse relative URLs easily */
    if ( base_server == NULL || set ) {
        /*
         * If we follow a 3XX redirect for the first page we are parsing
         * then these need to be updated so the base values use the new
         * location (e.g. www.wand.net.nz redirects to wand.net.nz).
         */
        if ( base_server ) {
            free(base_server);
        }
        if ( base_path ) {
            free(base_path);
        }
        /* schema might point to base_schema, so check before freeing it */
        if ( base_scheme && base_scheme != scheme ) {
            free(base_scheme);
            base_scheme = NULL;
        }

        base_server = strdup(server);
        base_path = strdup(path);
        if ( base_scheme != scheme ) {
            base_scheme = strdup(scheme);
        }
    }

    if ( url != orig_url ) {
        free(url);
    }
}



/*
 * Custom open socket callback function to bind source interface and addresses.
 * Libcurl provides the CURLOPT_INTERFACE option, but that will only take a
 * single interface/address. If both a source IPv4 and IPv6 address has been
 * set then we need to make sure to use the appropriate source address.
 *
 * We do this here by checking the family of the resolved address, and binding
 * the socket to our source address of the same family, if specified.
 */
static curl_socket_t open_socket(__attribute__((unused))void *clientp,
        curlsocktype purpose, struct curl_sockaddr *address) {

    int sock;

    if ( purpose != CURLSOCKTYPE_IPCXN ) {
        return CURL_SOCKET_BAD;
    }

    sock = socket(address->family, address->socktype, address->protocol);

    if ( options.dscp ) {
        struct socket_t sockets;
        /* wrap the socket in a socket_t so we can call other amp functions */
        memset(&sockets, 0, sizeof(sockets));
        switch ( address->family ) {
            case AF_INET: sockets.socket = sock; break;
            case AF_INET6: sockets.socket6 = sock; break;
            default: Log(LOG_ERR, "Unknown address family %d", address->family);
                     return CURL_SOCKET_BAD;
        };

        if ( set_dscp_socket_options(&sockets, options.dscp) < 0 ) {
            Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
            return CURL_SOCKET_BAD;
        }
    }

    /*
     * Bind to the device. We could use libcurl for this by setting
     * CURLOPT_INTERFACE, but for now we will use the same code that all
     * the other tests use.
     */
    if ( options.device ) {
        if ( bind_socket_to_device(sock, options.device) < 0 ) {
            return CURL_SOCKET_BAD;
        }
    }

    /* bind to a given source address if it was specified and is relevant */
    if ( options.sourcev4 || options.sourcev6 ) {
        struct addrinfo *addr = NULL;

        if ( options.sourcev4 && address->family == AF_INET ) {
            addr = get_numeric_address(options.sourcev4, NULL);
        } else if ( options.sourcev6 && address->family == AF_INET6 ) {
            addr = get_numeric_address(options.sourcev6, NULL);
        }

        if ( addr ) {
            if ( bind_socket_to_address(sock, addr) < 0 ) {
                freeaddrinfo(addr);
                return CURL_SOCKET_BAD;
            }

            freeaddrinfo(addr);
        }
    }

    return sock;
}



/*
 * Build the curl slist containing all the headers that we want to set on
 * the outgoing request.
 */
static struct curl_slist *config_request_headers(char *url, int caching) {

    struct curl_slist *slist = NULL;

    /*
     * give a different Accept string based on what type of file we think
     * we are trying to download (based on observations of FF3)
     */
    if ( strlen(url) > 4 &&
            (strncmp(url+(strlen(url)-4), ".png", 4) == 0 ||
             strncmp(url+(strlen(url)-4), ".gif", 4) == 0 ||
             strncmp(url+(strlen(url)-4), ".jpg", 4) == 0) ) {

        slist = curl_slist_append(slist,
                "Accept: image/png,image/*;q=0.8,*/*;q=0.5");

    } else if ( strlen(url) > 4 &&
            strncmp(url+(strlen(url)-4), ".css", 4) == 0 ) {

        slist = curl_slist_append(slist, "Accept: text/css,*/*;q=0.1");

    } else {
        slist = curl_slist_append(slist,
                "Accept: "
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8");
    }

    slist = curl_slist_append(slist, "Accept-Language: en-us,en;q=0.5");
    //slist = curl_slist_append(slist, "Accept-Encoding: gzip,deflate");
    slist = curl_slist_append(slist, "Accept-Encoding: gzip");
    slist = curl_slist_append(slist,
            "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7");
    slist = curl_slist_append(slist, "Keep-Alive: 300");
    slist = curl_slist_append(slist, "Connection: keep-alive");

    if ( caching ) {
        /* Pragma: no-cache is set by default, disable so we can hit caches */
        slist = curl_slist_append(slist, "Pragma:");

    } else {
        /* force a refresh of the page, ignoring caches */
        slist = curl_slist_append(slist, "Cache-Control: no-cache, max-age=0");
        slist = curl_slist_append(slist, "Pragma: no-cache");
    }

    return slist;
}



/*
 * Check if a given object is in the given queue.
 */
static int is_object_in_queue(char *object, struct object_stats_t *queue) {

    if ( object == NULL || queue == NULL ) {
        return 0;
    }

    if ( strcmp(object, queue->path) == 0 ) {
        return 1;
    }

    return is_object_in_queue(object, queue->next);
}



/*
 * Add an object to the given queue, returning the modified queue.
 */
static struct object_stats_t *add_object_to_queue(struct object_stats_t *object,
        struct object_stats_t *queue) {

    if ( object == NULL ) {
        return queue;
    }

    if ( queue == NULL ) {
        return object;
    }

    queue->next = add_object_to_queue(object, queue->next);
    return queue;
}



/*
 * Remove an object from a queue, returning the modified queue with the
 * object we removed in the result variable.
 */
static struct object_stats_t *pop_object_from_queue(char *object,
        struct object_stats_t *queue, struct object_stats_t **result) {

    if ( object == NULL ) {
        *result = NULL;
        return queue;
    }

    if ( queue == NULL ) {
        *result = NULL;
        return NULL;
    }

    assert(queue->path);
    if ( strcmp(object, queue->path) == 0 ) {
        *result = queue;
        return queue->next;
    }

    queue->next = pop_object_from_queue(object, queue->next, result);
    return queue;
}



/*
 * Create a new object on a given queue and return the modified queue. If
 * the object already exists then return the queue unmodified.
 */
static struct object_stats_t *create_object(char *host, char *path,
        struct object_stats_t *queue, int parse) {

    if ( queue == NULL ) {
        struct object_stats_t *object =
            (struct object_stats_t *)malloc(sizeof(struct object_stats_t));
        memset(object, 0, sizeof(struct object_stats_t));

        strncpy(object->server_name, host, MAX_DNS_NAME_LEN);
        strncpy(object->path, path, MAX_PATH_LEN);

        object->parse = parse;

        /* some counters dont default to zero */
        object->headers.max_age = -1;
        object->headers.s_maxage = -1;
        object->headers.x_cache = -1;
        object->headers.x_cache_lookup = -1;
        return object;
    }

    if(strcmp(queue->server_name, host) == 0) {
        if(strcmp(queue->path, path) == 0) {
            return queue;
        }
    }

    queue->next = create_object(host, path, queue->next, parse);
    return queue;
}



/*
 * Add a new URL for an object to be fetched (if it hasn't already been
 * fetched and isn't already in progress).
 */
struct server_stats_t *add_object(char *url, int parse) {

    struct server_stats_t *server;
    int i;
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];

    assert(url);

    /* for now, ignore URLs with spaces or URLs broken by chunked encoding */
    if ( strchr(url, ' ') != NULL || strchr(url, 0x0D) != NULL ) {
        return NULL;
    }

    split_url(url, host, path, parse);

    /* find the server that this object is being fetched from */
    server_list = get_server(host, server_list, &server);

    /* check the finished queue to make sure we don't already have the object */
    if ( is_object_in_queue(path, server->finished) ) {
        return server;
    }

    /* check the current pipelines as well to make sure it's not in progress */
    for ( i=0; i<server->num_pipelines; i++ ) {
        if ( is_object_in_queue(path, server->pipelines[i]) ) {
            return server;
        }
    }

    /* not finished and not in progress, try to add to the pending queue */
    server->pending = create_object(host, path, server->pending, parse);

    return server;
}



/*
 * Select which pipeline should be used to download the next object from a
 * server.
 */
static int select_pipeline(struct server_stats_t *server, uint32_t threshold) {
    int index = 0;
    uint32_t smallest_size;
    int smallest_index;
    int i;

    if ( server == NULL ) {
        return -1;
    }

    /*
     * No objects have been completed but there is something outstanding.
     * This means we are on the first object for this server and can't do
     * any pipelining till we complete it and check the headers.
     */
    if ( server->objects < 1 && server->pipelines[0] != NULL ) {
        return -1;
    }

    if ( server->objects < 1 && server->pipelines[0] == NULL ) {
        /* very first object, there is definitely room for that! */
        return 0;
    } else {
        /* data has been successfully received, try to queue another object */
        smallest_size = server->pipelining_maxrequests + 1;
        smallest_index = -1;

        for ( i=0; i<server->num_pipelines; i++ ) {
            struct object_stats_t *p = server->pipelines[index];
            /* check how full the current pipeline is */
            /* TODO do we really need to add this up every time? Or is it hard
             * to know when a pipeline completes something?
             */
            server->pipelen[index] = 0;
            while ( p != NULL ) {
                server->pipelen[index]++;
                p = p->next;
            }

            /*
             * if the current pipe has less than the threshold number of items
             * then just put the object there, regardless of the other pipes.
             */
            if ( server->pipelen[index] < threshold &&
                    server->pipelen[index] < server->pipelining_maxrequests) {
                return index;
            }

            /*
             * keep track of the smallest pipeline in case all are currently
             * past the threshold and there are no easy options.
             */
            if ( server->pipelen[index] < smallest_size ) {
                smallest_size = server->pipelen[i];
                smallest_index = i;
            };

            /* if there are too many objects queued then try the next pipe */
            index = (index + 1) % server->num_pipelines;
        }
    }

    /*
     * if they all have more than size_before_skip objects then put the new
     * object on the shortest pipeline that has space available
     */
    if ( smallest_size < server->pipelining_maxrequests ) {
        return smallest_index;
    }

    return -1;
}



/*
 * Remove the first object from the pending queue for this server and put it
 * on the end of the first pipeline that has room for it.
 *
 * TODO Pipeline selection algorithms might need some work.
 */
CURL *pipeline_next_object(CURLM *multi, struct server_stats_t *server) {

    struct object_stats_t *object;
    int pipeline;

    if ( server == NULL || server->pending == NULL ) {
        return NULL;
    }

    /* find the first available pipeline */
    pipeline = select_pipeline(server, options.pipe_size_before_skip);
    if ( pipeline < 0 ) {
        return NULL;
    }

    /* remove the first object from the pending queue and add it to the pipe */
    object = server->pending;
    server->pending = server->pending->next;
    object->next = NULL;
    server->pipelines[pipeline] =
        add_object_to_queue(object, server->pipelines[pipeline]);

//TODO move to function
    /*
     * Set up curl to fetch the appropriate url. Note that we have to save
     * this because curl < 7.17.0 won't copy the strings for us...
     */
    strncpy(object->url, object->server_name, MAX_DNS_NAME_LEN);
    strncat(object->url, object->path, MAX_URL_LEN - strlen(object->url) - 1);

    /*
     * Set the HTTP headers for this request. It's possible for different
     * headers to be set in each request so we need to check this every time.
     */
    object->handle = curl_easy_init();
    object->slist = config_request_headers(object->url, options.caching);
    curl_easy_setopt(object->handle, CURLOPT_HTTPHEADER, object->slist);

    /* if keep-alives are disabled then ensure a new connection */
    if ( !options.keep_alive ) {
        curl_easy_setopt(object->handle, CURLOPT_FRESH_CONNECT, 1);
        curl_easy_setopt(object->handle, CURLOPT_FORBID_REUSE, 1);
    }

    /* timeout anything that fails to connect in a reasonable time period */
    curl_easy_setopt(object->handle, CURLOPT_CONNECTTIMEOUT, 60); //XXX

    /* abort any transfers that do nothing for 30 seconds */
    curl_easy_setopt(object->handle, CURLOPT_LOW_SPEED_LIMIT, 1);
    curl_easy_setopt(object->handle, CURLOPT_LOW_SPEED_TIME, 30);

    /*
     * If an interface or address is specified then we need a custom socket
     * creation function to deal with it. Could pass in the options struct,
     * but it is currently global anyway.
     */
    if ( options.device || options.sourcev4 || options.sourcev6 ||
            options.dscp) {
        //curl_easy_setopt(object->handle, CURLOPT_OPENSOCKETDATA, &options);
        curl_easy_setopt(object->handle, CURLOPT_OPENSOCKETFUNCTION,
                open_socket);
    }

    /* if we have bound to a particular address family, use it exclusively */
    if ( options.forcev4 && !options.forcev6 ) {
        curl_easy_setopt(object->handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    } else if ( options.forcev6 && !options.forcev4 ) {
        curl_easy_setopt(object->handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
    } else {
        curl_easy_setopt(object->handle, CURLOPT_IPRESOLVE,
                CURL_IPRESOLVE_WHATEVER);
    }

    if ( options.parse && object->parse ) {
        /* this is the main page, parse the result for more objects */
        curl_easy_setopt(object->handle, CURLOPT_WRITEFUNCTION, parse_response);
    } else {
        /* this isn't the main page, set the referer and don't parse result */
        curl_easy_setopt(object->handle, CURLOPT_REFERER, options.url);
        /* TODO parse javascript and css for anything else we should get? */
        curl_easy_setopt(object->handle, CURLOPT_WRITEFUNCTION, do_nothing);
    }

    /*
     * Use the given proxy if specified. Passed straight through to libcurl,
     * expected format: [protocol://][user:password@]proxyhost[:port].
     * See https://curl.haxx.se/libcurl/c/CURLOPT_PROXY.html
     */
    if ( options.proxy ) {
        curl_easy_setopt(object->handle, CURLOPT_PROXY, options.proxy);
    }

    /* get all the response headers to parse for anything interesting */
    curl_easy_setopt(object->handle, CURLOPT_HEADERFUNCTION, parse_headers);
    curl_easy_setopt(object->handle, CURLOPT_WRITEHEADER, object);

    /* share the DNS cache between all handles, even on different multis */
    curl_easy_setopt(object->handle, CURLOPT_SHARE, share_handle);

    curl_easy_setopt(object->handle, CURLOPT_ENCODING, "gzip");
    curl_easy_setopt(object->handle, CURLOPT_URL, object->url);
    curl_easy_setopt(object->handle, CURLOPT_USERAGENT, options.useragent);
    curl_easy_setopt(object->handle, CURLOPT_SSLVERSION, options.sslversion);

#if 0
    /* use the native windows CA store if possible */
#if _WIN32 && LIBCURL_VERSION_NUM >= 0x074700
    curl_easy_setopt(object->handle, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif
#endif

#if _WIN32
    /*
     * set this manually for now, as CURLSSLOPT_NATIVE_CA doesn't seem to do
     * what we need/expect?
     */
    curl_easy_setopt(object->handle, CURLOPT_CAINFO,
            AMP_CONFIG_DIR "ca-certificates.crt");
#endif

    /* save the time that fetching started for this object */
    gettimeofday(&object->start, NULL);

    /* this might be the first object we've tried to fetch from this server */
    if ( server->start.tv_sec == 0 && server->start.tv_usec == 0 ) {
        server->start.tv_sec = server->end.tv_sec = object->start.tv_sec;
        server->start.tv_usec = server->end.tv_usec = object->start.tv_usec;

        /* this might also be the first object we've fetched total */
        if ( global.start.tv_sec == 0 && global.start.tv_usec == 0 ) {
            global.start.tv_sec = global.end.tv_sec = object->start.tv_sec;
            global.start.tv_usec = global.end.tv_usec = object->start.tv_usec;
        }
    }

    if ( curl_multi_add_handle(multi, object->handle) != 0 ) {
        Log(LOG_ERR, "Failed to add multi handle, aborting\n");
        exit(EXIT_FAILURE);
    }

    return object->handle;
}



/*
 * Save the statistics about an object that has been fetched.
 */
static struct object_stats_t *save_stats(CURL *handle) {
    char *url;
    struct timeval end;
    struct object_stats_t *object;
    struct server_stats_t *server;
    double lookup, connect, start_transfer, total_time;
    double bytes;
    long connect_count;
    long code;
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];
    int i;

    gettimeofday(&end, NULL);

    curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &url);
    split_url(url, host, path, 0);
    get_server(host, server_list, &server);

    /* CURLINFO_PRIMARY_IP was added in 7.19.0 */
#if LIBCURL_VERSION_NUM >= 0x071300
    if ( strcmp(server->address, "0.0.0.0") == 0 ) {
        char *address = NULL;
        curl_easy_getinfo(handle, CURLINFO_PRIMARY_IP, &address);
        if ( address != NULL && strlen(address) > 0 ) {
            strncpy(server->address, address, MAX_ADDR_LEN);
        }
    }
#endif

    curl_easy_getinfo(handle, CURLINFO_NAMELOOKUP_TIME, &lookup);
    curl_easy_getinfo(handle, CURLINFO_CONNECT_TIME, &connect);
    curl_easy_getinfo(handle, CURLINFO_STARTTRANSFER_TIME, &start_transfer);
    curl_easy_getinfo(handle, CURLINFO_TOTAL_TIME, &total_time);
    curl_easy_getinfo(handle, CURLINFO_SIZE_DOWNLOAD, &bytes);
    curl_easy_getinfo(handle, CURLINFO_NUM_CONNECTS, &connect_count);
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &code);

    /* XXX if the server never returned a response (couldn't resolve or it
     * timed out) then we are going to ignore this object in the global stats
     * because otherwise we get object fetch durations that are based on the
     * arbitrary timeouts we have set in curl. THIS IS STILL MISLEADING but
     * works well enough with nntsc, which currently only stores global stats
     * to make some basic graphs.
     *
     * It looks like the correct approach will be to store counts of both
     * successful and failed object fetches, as well as maybe the times of
     * both the last successful and last failed fetches. This information can
     * be added to the tooltips (or possibly shown directly on the graph?) so
     * that it is obvious when a result is unusual because of failed fetches.
     * This requires updating the protocol/ampsave, which is why we don't want
     * to do it just now.
     */
    server->end.tv_sec = end.tv_sec;
    server->end.tv_usec = end.tv_usec;
    if ( code > 0 ) {
        global.bytes += bytes;
        global.objects++;
        server->bytes += bytes;
        server->objects++;
        global.end.tv_sec = end.tv_sec;
        global.end.tv_usec = end.tv_usec;
    } else {
        global.failed_objects++;
        server->failed_objects++;
    }

    /* find object in queue */
    for ( i = 0; i < server->num_pipelines; i++ ) {
        server->pipelines[i] =
            pop_object_from_queue(path, server->pipelines[i], &object);
        if ( object != NULL ) {
            object->next = NULL;
            break;
        }
    }

    assert(object);
    object->end.tv_sec = end.tv_sec;
    object->end.tv_usec = end.tv_usec;
    object->lookup = lookup;
    object->connect = connect;
    object->start_transfer = start_transfer;
    object->total_time = total_time;
    object->size = bytes;
    object->connect_count = connect_count;
    object->code = code;
    object->pipeline = i;
    server->finished = add_object_to_queue(object, server->finished);

    curl_slist_free_all(object->slist);

    return object;
}



/*
 * Deal with any messages from the curl multi handle - this could be objects
 * that have been successfully fetched, failed to fetch, redirected, etc.
 */
static void check_messages(CURLM *multi, int *running_handles) {
    CURLMsg *msg;
    int msg_queue;
    struct server_stats_t *server;
    struct object_stats_t *object;
    char *url;
    double bytes;
    CURL *handle;
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];
    struct server_stats_t *redirect = NULL;

    /* check for messages from the transfers - errors or completed transfers */
    while ( (msg = curl_multi_info_read(multi, &msg_queue)) ) {

        /* report on any errors received */
        if ( msg->msg != CURLMSG_DONE ) {
            Log(LOG_WARNING, "unexpected curlmsg %d\n", msg->msg);
            continue;
        }

        /* object is finished downloading, save some stats */
        handle = msg->easy_handle;

        curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &url);
        curl_easy_getinfo(msg->easy_handle, CURLINFO_SIZE_DOWNLOAD, &bytes);

        if ( msg->data.result != 0 ) {
            Log(LOG_WARNING, "%s <%s> (%fb)\n",
                    curl_easy_strerror(msg->data.result), url, bytes);
            /*
             * If we fail to resolve or connect to the first host then stop
             * the test and don't record an object.
             */
            if ( (msg->data.result == CURLE_COULDNT_RESOLVE_HOST ||
                        msg->data.result == CURLE_COULDNT_RESOLVE_PROXY ||
                        msg->data.result == CURLE_COULDNT_CONNECT ||
                        msg->data.result == CURLE_SSL_CONNECT_ERROR) &&
                    server_list && server_list->next == NULL &&
                    server_list->finished == NULL ) {
                break;
            }
        }

        object = save_stats(msg->easy_handle);
        curl_multi_remove_handle(multi, handle);

        /* split the url before we cleanup the handle (and lose the pointer) */
        split_url(url, (char*)&host, (char*)&path, 0);

        /* no longer participate in the shared dns cache with this handle */
        curl_easy_setopt(handle, CURLOPT_SHARE, NULL);
        curl_easy_cleanup(handle);

        /* if this object was a redirect, then try to follow it */
        if ( object->location != NULL && (
                    object->code == 301 || object->code == 302 ||
                    object->code == 303 || /*object->code == 305 || */
                    object->code == 307 || object->code == 308) ) {
            /* add the new location to the queue to be fetched */
            Log(LOG_DEBUG, "Following %d redirect to %s", object->code,
                    object->location);
            redirect = add_object(object->location, object->parse);
        }

        get_server(host, server_list, &server);
        if ( server == NULL ) {
            Log(LOG_ERR, "getServer() failed for '%s'\n", host);
            exit(EXIT_FAILURE);
        }

        /* queue the redirected item if it is from another server */
        if ( redirect != server ) {
            if ( pipeline_next_object(multi, redirect) != NULL ) {
                (*running_handles)++;
            }
        }

        /* queue any more objects that we have for this server */
        if ( pipeline_next_object(multi, server) != NULL ) {
            (*running_handles)++;
        }
    }
}



/*
 * Ask curl how long we should wait before trying again, or use a fixed wait
 * time if curl is unable to tell us.
 */
static long get_wait_timeout(CURLM *multi) {
    long wait;

#if HAVE_CURL_MULTI_TIMEOUT
    if ( curl_multi_timeout(multi, &wait) ) {
        Log(LOG_ERR, "error calling curl_multi_timeout!\n");
        exit(EXIT_FAILURE);
    }

    /* it's polite to wait at least a short time */
    if ( wait < 0 ) {
        wait = 100;
    }
#else
    wait = 100;
#endif

    return wait;
}



/*
 * Fetch the given URL.
 */
static int fetch(char *url) {
    struct server_stats_t *server;
    int running_handles = -1;
    int max_fd;
    struct timeval timeout;
    fd_set read_fdset, write_fdset, except_fdset;
    int result = 0;
    long wait;

    /* add the primary server/path that is being fetched */
    add_object(url, 1);

    while ( running_handles ) {
        /* force start any connections that need it */
        for ( server = server_list; server != NULL; server = server->next ) {
            pipeline_next_object(multi, server);
        }

        /* call curl_multi_perform() until it no longer wants to be run */
        while ( curl_multi_perform(multi, &running_handles) ==
                CURLM_CALL_MULTI_PERFORM ) {
            /* keep calling curl_multi_perform() */
        }

        /*
         * If there are any running handles then determine which file handles
         * involved are ready for reading/writing
         */
        if ( running_handles ) {
            do {
                FD_ZERO(&read_fdset);
                FD_ZERO(&write_fdset);
                FD_ZERO(&except_fdset);
                max_fd = -1;

                /* add any running file descriptors to the lists */
                if ( curl_multi_fdset(multi, &read_fdset, &write_fdset,
                            &except_fdset, &max_fd)) {
                    Log(LOG_ERR, "error calling curl_multi_fdset!\n");
                    exit(EXIT_FAILURE);
                }

                /* check how long we should be waiting for before timing out */
                wait = get_wait_timeout(multi);

                /* if there are no descriptors, sleep and skip the select */
                if ( max_fd < 0 ) {
                    usleep(wait / 1000);
                    break;
                }

                /* TODO update timeout values if interrupted */
                timeout.tv_sec = wait / 1000;
                timeout.tv_usec = (wait % 1000) * 1000;

                result = select(max_fd + 1, &read_fdset, &write_fdset,
                        &except_fdset, &timeout);

            } while ( result < 0 && errno == EINTR );

            if ( result < 0 ) {
                Log(LOG_ERR, "error calling select(): %s", strerror(errno));
                exit(EXIT_FAILURE);
            }
        }

        /* check if there are any completed transfers */
        check_messages(multi, &running_handles);
    }

    curl_multi_cleanup(multi);

    return result;
}



/*
 * Determine which configuration option to use to control the maximum number
 * of connections to a server and how many outstanding requests are allowed.
 */
static void configure_global_max_requests(struct opt_t *opt) {
    /* how many connections are we allowed to have per server */
    if ( opt->keep_alive ) {
        total_pipelines = opt->max_persistent_connections_per_server;

        /* pipelining off is the same as only having 1 request outstanding */
        if ( opt->pipelining ) {
            total_requests = opt->pipelining_maxrequests;
        } else {
            total_requests = 1;
        }

    } else {
        total_pipelines = opt->max_connections_per_server;
        total_requests = 1;
    }
}



/*
 * Force curl to use a specific SSL version.
 */
static void set_ssl_version(long *sslv, char *optarg) {
    if ( strncmp(optarg, "sslv3", 5) == 0 ) {
        Log(LOG_DEBUG, "Forcing use of SSLv3\n");
        *sslv = CURL_SSLVERSION_SSLv3;
    } else if ( strncmp(optarg, "tlsv1", 5) == 0 ) {
        Log(LOG_DEBUG, "Forcing use of TLSv1\n");
        *sslv = CURL_SSLVERSION_TLSv1;
#if LIBCURL_VERSION_NUM >= 0x072200
    /* Targeting specific TLS1.x versions was added in libcurl 7.34.0 */
    } else if ( strncmp(optarg, "tlsv1.0", 7) == 0 ) {
        Log(LOG_DEBUG, "Forcing use of TLSv1.0\n");
        *sslv = CURL_SSLVERSION_TLSv1_0;
    } else if ( strncmp(optarg, "tlsv1.1", 7) == 0 ) {
        Log(LOG_DEBUG, "Forcing use of TLSv1.1\n");
        *sslv = CURL_SSLVERSION_TLSv1_1;
    } else if ( strncmp(optarg, "tlsv1.2", 7) == 0 ) {
        Log(LOG_DEBUG, "Forcing use of TLSv1.2\n");
        *sslv = CURL_SSLVERSION_TLSv1_2;
#endif
    } else {
        Log(LOG_WARNING,
                "SSL version '%s' not recognised. Using default SSL version\n",
                optarg);
        *sslv = CURL_SSLVERSION_DEFAULT;
    }
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-http [-cdhkpvx] -u <url> [-a user-agent] [-m max-con]\n"
            "                [-o max-persistent] [-r max-pipelined-requests]\n"
            "                [-P proxy] [-s max-con-per-server]\n"
            "                [-S sslversion][-z pipe-size] [-Q codepoint]\n"
            "                [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
            "\n");

    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --user-agent     <agent>   "
            "Specify User-Agent string\n");
    fprintf(stderr, "  -c, --cached                   "
            "Allow cached content (def:false)\n");
    fprintf(stderr, "  -d, --dontparse                "
            "Don't parse fetched URL for more objects\n");
    fprintf(stderr, "  -k, --no-keep-alive            "
            "Disable keep-alives (def:enabled)\n");
    fprintf(stderr, "  -m, --max-con        <max>     "
            "Maximum number of connections (def:24)\n");
    fprintf(stderr, "  -o, --max-persistent <max>     "
            "Max persistent connections per server (def:2)\n");
    fprintf(stderr, "  -p, --pipeline                 "
            "Enable pipelining (def:disabled)\n");
    fprintf(stderr, "  -P, --proxy          <proxy>   "
            "[protocol://][user:password@]proxyhost[:port]\n");
    fprintf(stderr, "  -r, --max-pipelined  <max>     "
            "Maximum number of requests per pipeline (def:4)\n");
    fprintf(stderr, "  -s, --max-per-server <max>     "
            "Maximum connections per server (def:8)\n");
    /* TODO libcurl 7.34.0 or newer opens up other ssl version options */
    fprintf(stderr, "  -S, --sslversion     <version> "
            "Force SSL version (sslv3, tlsv1, etc)\n");
    fprintf(stderr, "  -u, --url            <url>     "
            "URL of the page to fetch\n");
    fprintf(stderr, "  -z, --pipe-size      <max>     "
            "Active requests before using new pipe (def:2)\n");

    print_interface_usage();
    print_generic_usage();
}



/*
 * TODO const up the dest arguments so cant be changed?
 */
//XXX dests should not have anything in it?
//XXX how about dests has the hostname/address and url just appends to that?
amp_test_result_t* run_http(int argc, char *argv[],
        __attribute__((unused))int count,
        __attribute__((unused))struct addrinfo **dests) {
    int opt;
    amp_test_result_t *result;
    //struct opt_t options;

    Log(LOG_DEBUG, "Starting HTTP test");

    /* set some sensible defaults */
    options.url[0] = '\0';
    options.keep_alive = 1;
    options.max_connections = 24;
    options.max_connections_per_server = 8;
    options.max_persistent_connections_per_server = 2;
    options.pipelining = 0;
    options.pipelining_maxrequests = 4;
    options.caching = 0;
    options.parse = 1;
    options.pipe_size_before_skip = 2;
    options.device = NULL;
    options.forcev4 = 0;
    options.forcev6 = 0;
    options.sourcev4 = NULL;
    options.sourcev6 = NULL;
    options.sslversion = CURL_SSLVERSION_DEFAULT;
    options.dscp = DEFAULT_DSCP_VALUE;
    options.useragent = DEFAULT_HTTP_USERAGENT;
    options.proxy = NULL;

    while ( (opt = getopt_long(argc, argv,
                    "a:cdkm:o:pP:r:s:S:u:z:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4': options.forcev4 = 1;
                      options.sourcev4 = parse_optional_argument(argv);
                      break;
            case '6': options.forcev6 = 1;
                      options.sourcev6 = parse_optional_argument(argv);
                      break;
            case 'I': options.device = optarg; break;
            case 'Q': if ( parse_dscp_value(optarg, &options.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': /* option does nothing for this test */ break;
            case 'a': options.useragent = optarg; break;
            case 'c': options.caching = 1; break;
            case 'd': options.parse = 0; break;
	    case 'k': options.keep_alive = 0; break;
	    case 'm': options.max_connections = atoi(optarg); break;
	    case 'o': options.max_persistent_connections_per_server =
                      atoi(optarg); break;
            case 'p':
#if LIBCURL_VERSION_NUM >= 0x071000
                      options.pipelining = 1;
#else
                      Log(LOG_WARNING,
                              "libcurl version too old to support pipelining "
                              "(found %s, required >= 7.16.0), disabled\n",
                              LIBCURL_VERSION);
#endif
                      break;
            case 'P': options.proxy = optarg; break;
            case 'r': options.pipelining_maxrequests = atoi(optarg); break;
	    case 's': options.max_connections_per_server = atoi(optarg); break;
            case 'S': set_ssl_version(&options.sslversion, optarg); break;
	    case 'u': split_url(optarg, options.host, options.path, 1);
                      strncpy(options.url, options.host, MAX_DNS_NAME_LEN);
                      strncat(options.url, options.path, MAX_PATH_LEN);
                      break;
            case 'z': options.pipe_size_before_skip = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS); break;
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
	    case 'h': usage(); exit(EXIT_SUCCESS); break;
	    default: usage(); exit(EXIT_FAILURE); break;
	};
    }

    if ( strlen(options.url) == 0 ||
            options.host == NULL || options.path == NULL ) {
        usage();
        exit(EXIT_FAILURE);
    }

    configure_global_max_requests(&options);

    curl_global_init(CURL_GLOBAL_ALL);

    if ( !(multi = curl_multi_init()) ) {
        Log(LOG_ERR, "Failed to initialise CURL multi handle, aborting\n");
        exit(EXIT_FAILURE);
    }
#if LIBCURL_VERSION_NUM >= 0x071000
    if ( options.pipelining ) {
        curl_multi_setopt(multi, CURLMOPT_PIPELINING, 1);
    }
#endif

    /*
     * Setup a share handle to share the dns cache between all handles. Don't
     * bother with setting lock functions as this test is single threaded, we
     * won't be accessing share_handle in multiple locations at the same time.
     */
    share_handle = curl_share_init();
    curl_share_setopt(share_handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

    fetch(options.path);

    curl_share_cleanup(share_handle);
    curl_global_cleanup();

    /* send report */
    result = report_results(&global.start, server_list, &options);

    /* TODO, free everything */
    //free(server_list);

    return result;
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_HTTP;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("http");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 300;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_http;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_http;

    /* the http test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the http test a SIGINT warning */
    new_test->sigint = 0;

    return new_test;
}


#if UNIT_TEST
void amp_test_http_split_url(char *orig_url, char *server, char *path, int set){
    split_url(orig_url, server, path, set);
}
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        struct server_stats_t *server_stats, struct opt_t *opt) {
    return report_results(start_time, server_stats, opt);
}
#endif
