#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <malloc.h>
#include <string.h>

//TODO rename files and headers better?
#include "testlib.h"
#include "http.h"
#include "servers.h"
#include "parsers.h"
#include "output.h"

#include <inttypes.h>
#include <fcntl.h>

#include "curl/curl.h"


CURLSH *share_handle = NULL;
struct server_stats_t *server_list = NULL;
int total_pipelines;
int total_requests;
struct opt_t options;



/*
 * Fill in the standard report header with options that were set
 */
static void report_header_results(struct http_report_header_t *header,
        struct opt_t *opt) {

    assert(header);
    assert(opt);

    header->version = AMP_HTTP_TEST_VERSION;
    strncpy(header->url, opt->url, MAX_URL_LEN);
    header->duration = ((global.end.tv_sec - global.start.tv_sec) * 1000) +
        (global.end.tv_usec - global.start.tv_usec + 500) / 1000;
    header->bytes = global.bytes;
    header->total_objects = global.objects;
    header->total_servers = global.servers;
    header->persist = opt->keep_alive;//XXX different names?
    header->max_connections = opt->max_connections;
    header->max_connections_per_server = opt->max_connections_per_server;
    header->max_persistent_connections_per_server =
        opt->max_persistent_connections_per_server;
    header->pipelining = opt->pipelining;
    header->pipelining_maxrequests = opt->pipelining_maxrequests;
    header->caching = opt->caching;
}



/*
 * Report on a single object.
 */
static void report_object_results(struct http_report_object_t *object,
        struct object_stats_t *info) {

    assert(object);
    assert(info);

    strncpy(object->path, info->path, MAX_PATH_LEN);
    object->start.tv_sec = info->start.tv_sec;
    object->start.tv_usec = info->start.tv_usec;
    object->end.tv_sec = info->end.tv_sec;
    object->end.tv_usec = info->end.tv_usec;
    FLOAT_TO_TV(info->lookup, object->lookup);
    FLOAT_TO_TV(info->connect, object->connect);
    FLOAT_TO_TV(info->start_transfer, object->start_transfer);
    FLOAT_TO_TV(info->total_time, object->total_time);
    object->code = info->code;
    object->size = info->size;
    memcpy(&object->headers, &info->headers, sizeof(struct cache_headers_t));
    object->connect_count = info->connect_count;
    object->pipeline = info->pipeline;
}



/*
 * Report on a single server and all objects that were fetched from it.
 */
static int report_server_results(struct http_report_server_t *server,
        struct server_stats_t *server_info) {

    uint8_t reported_objects = 0;
    struct http_report_object_t *object;
    struct object_stats_t *object_info;

    assert(server);
    assert(server_info);

    strncpy(server->hostname, server_info->server_name, MAX_DNS_NAME_LEN);
    strncpy(server->address, server_info->address, MAX_ADDR_LEN);
    server->start.tv_sec = server_info->start.tv_sec;
    server->start.tv_usec = server_info->start.tv_usec;
    server->end.tv_sec = server_info->end.tv_sec;
    server->end.tv_usec = server_info->end.tv_usec;
    server->bytes = server_info->bytes;
    server->objects = server_info->objects;

    for ( object_info = server_info->finished; object_info != NULL;
            object_info = object_info->next ) {

        object = (struct http_report_object_t *)(((char *)server) +
                sizeof(struct http_report_server_t) +
                (reported_objects * sizeof(struct http_report_object_t)));
        report_object_results(object, object_info);
        reported_objects++;
    }

    assert(reported_objects == server_info->objects);
    return server_info->objects;
}



/*
 *
 */
static void report_results(struct timeval *start_time,
        struct server_stats_t *servers, struct opt_t *opt) {
    char *buffer;
    struct http_report_header_t *header;
    struct http_report_server_t *server;
    struct server_stats_t *tmpsrv;
    uint32_t reported_objects = 0;
    uint32_t reported_servers = 0;
    int len;

    Log(LOG_DEBUG, "Building http report, url:%s\n", opt->url);

    /* allocate space for all our results - XXX could this get too large? */
    len = sizeof(struct http_report_header_t) +
	(global.servers * sizeof(struct http_report_server_t)) +
        (global.objects * sizeof(struct http_report_object_t));
    buffer = malloc(len);
    memset(buffer, 0, len);

    /* single header at the start of the buffer describes the test options */
    header = (struct http_report_header_t *)buffer;
    report_header_results(header, opt);

    /* add results for all the servers that data was fetched from */
    for ( tmpsrv = servers; tmpsrv != NULL; tmpsrv = tmpsrv->next ) {
        assert(reported_servers < global.servers);
        /* global information regarding this particular server */
	server = (struct http_report_server_t *)(buffer +
		sizeof(struct http_report_header_t) +
		reported_servers * sizeof(struct http_report_server_t) +
                reported_objects * sizeof(struct http_report_object_t));

        reported_objects += report_server_results(server, tmpsrv);

        Log(LOG_DEBUG, "server result %d: %s\n", reported_servers,
                tmpsrv->address);
        reported_servers++;
    }

    assert(global.servers == reported_servers);
    assert(global.objects == reported_objects);

    report(AMP_TEST_HTTP, (uint64_t)start_time->tv_sec, (void*)buffer, len);
    free(buffer);
}



/*
 * Split URL into server and path components. Based on code originally from
 * the first HTTP test in AMP.
 */
static void split_url(char *url, char *server, char *path) {
    static char *base_server = NULL;
    static char *base_path = NULL;
    char *start;
    char *end;
    int length;

    assert(url);
    assert(server);
    assert(path);

    /* strip initial protocol portion, currently only understand http/https */
    if ( strncasecmp(url, "http://", 7) == 0 ) {
        /* full url, treat as normal */
        start = url + 7;
    } else if ( strncasecmp(url, "https://", 8) == 0 ) {
        /* full url, treat as normal */
        start = url + 8;
    } else if ( strncasecmp(url, "//", 2) == 0 ) {
        /*
         * 2 slashes means it's a remote URL accessed over the same protocol
         * as the current document, which for now we will assume is HTTP
         */
        start = url + 2;
    } else if ( strncasecmp(url, "/", 1) == 0 ) {
        /* one slash makes this an absolute path on the current host */
        assert(base_server);
        strncpy(server, base_server, MAX_DNS_NAME_LEN);
        strncpy(path, url, MAX_PATH_LEN);
        //printf("absolute url, making it: %s %s\n", server, path);
        return;
    } else if ( base_server != NULL && base_path != NULL ) {
        /* TODO an initial url like www.wand.net.nz without a protocol
         * specifier will hit here later in the test when trying to look up
         * the object and will interpret the result as a relative path, which
         * is incorrect (e.g. /www.wand.net.nz).
         */
        /* no initial slashes but not the first url, treat as a relative path */
        strncpy(server, base_server, MAX_DNS_NAME_LEN);
        /* strip the last part of the path, back to the final slash */
        //strncpy(path, base_path, MAX_PATH_LEN);
        //strncat(path, url, MAX_PATH_LEN - strlen(base_path) - 1);
        //XXX there has to be a slash, because we add one if there isnt!
        char *slash = rindex(base_path, '/');
        memset(path, 0, MAX_PATH_LEN);
        //printf("base: %s (path already has %s)\n", base_path, path);
        strncpy(path, base_path, (slash - base_path) + 1);
        //printf("1: %s\n", path);
        strncat(path, url, MAX_PATH_LEN - strlen(base_path) - 1);
        //printf("given url: %s\n", url);
        //printf("relative url, making it: %s %s\n", server, path);
        return;
    } else {
        /* treat as a URL that is missing the protocol */
        start = url;
    }

    /* determine end of the host portion and extract the remaining path */
    if ( (end = index(start, '/')) == NULL ) {
        end = start + strlen(start);
        strncpy(path, "/\0", 2);
    } else {
        strncpy(path, end, MAX_PATH_LEN);
        path[MAX_PATH_LEN - 1] = '\0';
    }

    /* save the host portion also */
    length = end - start;
    assert(length < MAX_DNS_NAME_LEN);
    strncpy(server, start, length);
    server[length] = '\0';

    /* save these so we can later parse relative URLs easily */
    if ( base_server == NULL ) {
        base_server = strdup(server);
        base_path = strdup(path);
        //printf("setting base server/path: %s %s\n", base_server, base_path);
    }
}



/*
 *
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
 *
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
 *
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
 *
 */
static struct object_stats_t *create_object(char *host, char *path,
        struct object_stats_t *queue) {

    if ( queue == NULL ) {
        struct object_stats_t *object =
            (struct object_stats_t *)malloc(sizeof(struct object_stats_t));
        memset(object, 0, sizeof(struct object_stats_t));

        strncpy(object->server_name, host, MAX_DNS_NAME_LEN);
        strncpy(object->path, path, MAX_URL_LEN);

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

    queue->next = create_object(host, path, queue->next);
    return queue;
}

/*
 *
 */
struct server_stats_t *add_object(char *url) {

    struct server_stats_t *server;
    int i;
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];

    assert(url);

    /* for now, ignore URLs with spaces or URLs broken by chunked encoding */
    if ( index(url, ' ') != NULL || index(url, 0x0D) != NULL ) {
        return NULL;
    }

    split_url(url, host, path);

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
    server->pending = create_object(host, path, server->pending);

    return server;
}



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
CURL *pipeline_next_object(struct server_stats_t *server) {

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

    /* timeout anything that fails to connect in a reasonable time period */
    curl_easy_setopt(object->handle, CURLOPT_CONNECTTIMEOUT, 60); //XXX

    /* abort any transfers that do nothing for 30 seconds */
    curl_easy_setopt(object->handle, CURLOPT_LOW_SPEED_LIMIT, 1);
    curl_easy_setopt(object->handle, CURLOPT_LOW_SPEED_TIME, 30);

    //if ( strcmp(options.url, object->url) == 0 ) {
    if ( strcmp(options.host, object->server_name) == 0 &&
            strcmp(options.path, object->path) == 0 ) {
        /* this is the main page, parse the result for more objects */
        curl_easy_setopt(object->handle, CURLOPT_WRITEFUNCTION, parse_response);
    } else {
        /* this isn't the main page, set the referer and don't parse result */
        curl_easy_setopt(object->handle, CURLOPT_REFERER, options.url);
        /* TODO parse javascript and css for anything else we should get? */
        curl_easy_setopt(object->handle, CURLOPT_WRITEFUNCTION, do_nothing);
    }

    /* get all the response headers to parse for anything interesting */
    curl_easy_setopt(object->handle, CURLOPT_HEADERFUNCTION, parse_headers);
    curl_easy_setopt(object->handle, CURLOPT_WRITEHEADER, object);

    /* share the DNS cache between all handles, even on different multis */
    curl_easy_setopt(object->handle, CURLOPT_SHARE, share_handle);

    curl_easy_setopt(object->handle, CURLOPT_ENCODING, "gzip");
    curl_easy_setopt(object->handle, CURLOPT_URL, object->url);
    curl_easy_setopt(object->handle, CURLOPT_USERAGENT, "AMP HTTP test agent");

    if ( server->multi[pipeline] == 0 ) {
        if ( !(server->multi[pipeline] = curl_multi_init()) ) {
            Log(LOG_ERR, "Failed to initialise CURL, aborting\n");
            exit(1);
        }
#if LIBCURL_VERSION_NUM >= 0x071000
        if ( options.pipelining ) {
            curl_multi_setopt(server->multi[pipeline], CURLMOPT_PIPELINING, 1);
        }
#endif
    }

    /* save the time that this server became active */
    gettimeofday(&object->start, NULL);
    if ( server->start.tv_sec == 0 && server->start.tv_usec == 0 ) {
        server->start.tv_sec = object->start.tv_sec;
        server->start.tv_usec = object->start.tv_usec;
    }

    if ( curl_multi_add_handle(server->multi[pipeline], object->handle) != 0 ) {
        Log(LOG_ERR, "Failed to add multi handle, aborting\n");
        exit(1);
    }

    return object->handle;
}



static void save_stats(CURL *handle, int pipeline) {
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
    split_url(url, host, path);
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

    global.bytes += bytes;
    global.objects++;
    server->bytes += bytes;
    server->objects++;
    server->end.tv_sec = end.tv_sec;
    server->end.tv_usec = end.tv_usec;
    global.end.tv_sec = end.tv_sec;
    global.end.tv_usec = end.tv_usec;

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
    object->pipeline = pipeline;
    server->finished = add_object_to_queue(object, server->finished);

    curl_slist_free_all(object->slist);
}


/*
 *
 */
static void check_messages(CURLM *multi, int *running_handles, int pipeline) {
    CURLMsg *msg;
    int msg_queue;
    struct server_stats_t *server;
    char *url;
    double bytes;
    CURL *handle;
    char host[MAX_DNS_NAME_LEN];
    char path[MAX_PATH_LEN];

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
            Log(LOG_WARNING, "R: %d - %s <%s> (%fb)\n", msg->data.result,
                    curl_easy_strerror(msg->data.result), url, bytes);
            //TODO should we break out of loop or anything here?
        }

        save_stats(msg->easy_handle, pipeline);
        curl_multi_remove_handle(multi, handle);

        /* split the url before we cleanup the handle (and lose the pointer) */
        split_url(url, (char*)&host, (char*)&path);

        /* no longer participate in the shared dns cache with this handle */
        curl_easy_setopt(handle, CURLOPT_SHARE, NULL);
        curl_easy_cleanup(handle);

        /* queue any more objects that we have for that server */
        get_server(host, server_list, &server);
        if ( server == NULL ) {
            Log(LOG_ERR, "getServer() failed for '%s'\n", host);
            exit(1);
        }

        /* add another object if there are more to come */
        if ( pipeline_next_object(server) != NULL ) {
            (*running_handles)++;
        }
    }
}


/*
 * TODO this function is way too long
 */
static int fetch(char *url) {
    struct server_stats_t *server;
    int running_handles = -1;
    int data_outstanding;
    int max_fd;
    struct timeval timeout;
    fd_set read_fdset, write_fdset, except_fdset;
    CURLM *multi;
    int result = 0;
    long wait;
    int index;
    int j;

    /*
     * Setup a share handle to share the dns cache between all handles. Don't
     * bother with setting lock functions as this test is single threaded, we
     * won't be accessing share_handle in multiple locations at the same time.
     */
    share_handle = curl_share_init();
    curl_share_setopt(share_handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

    /* add the primary server/path that is being fetched */
    add_object(url);

    pipeline_next_object(server_list);

    while ( running_handles ) {
        /* call curl_multi_perform() until it no longer wants to be run.
         * XXX thought it might be useful to round-robin it across all
         * connections, but now I'm not sure that offers any advantage over
         * dealing with each one in turn
         */
        data_outstanding = 1;
        while ( data_outstanding ) {
            data_outstanding = 0;
            /* check each server to find running handles */
            for ( server = server_list; server != NULL; server=server->next ) {
                /* force start any new connections that need it */
                pipeline_next_object(server);

                /* check each multi handle the server has */
                for ( index = 0; index < server->num_pipelines; index++ ) {
                    multi = server->multi[index];
                    /* not all of them will always be connected */
                    if ( multi == NULL ) {
                        continue;
                    }
                    /* set flag if we need to call curl_multi_perform again */
                    if ( curl_multi_perform(multi,
                                &server->running_handles[index]) ==
                            CURLM_CALL_MULTI_PERFORM ) {
                        data_outstanding = 1;
                    }
                }
            }
        }

        /* fill the FD sets for each server and count the running handles */
        running_handles = 0;
        for ( server = server_list; server != NULL; server = server->next ) {
            /* for each multi handle the server has */
            for ( index = 0; index < server->num_pipelines; index++ ) {
                multi = server->multi[index];
                running_handles += server->running_handles[index];

                /* zero fdsets regardless of there being running handles */
                FD_ZERO(&server->read_fdset[index]);
                FD_ZERO(&server->write_fdset[index]);
                FD_ZERO(&server->except_fdset[index]);

                /* add any running file descriptors to the lists */
                if ( server->running_handles[index] ) {
                    /* get curl file descriptors */
                    if ( curl_multi_fdset(multi, &server->read_fdset[index],
                                &server->write_fdset[index],
                                &server->except_fdset[index],
                                &server->max_fd[index])) {
                        Log(LOG_ERR, "error calling curl_multi_fdset!\n");
                        exit(-1);
                    }
                }
            }
        }


        if ( running_handles ) {
            /* select on all running descriptors to find ones that are ready */
            do {
                FD_ZERO(&read_fdset);
                FD_ZERO(&write_fdset);
                FD_ZERO(&except_fdset);
                max_fd = -1;

                /* add all the file descriptors */
                for ( server=server_list; server != NULL; server=server->next) {
                    for ( index = 0; index < server->num_pipelines; index++ ) {
                        if ( server->pipelines[index] != NULL ) {
                            if ( server->max_fd[index] > max_fd ) {
                                max_fd = server->max_fd[index];
                            }

                            for ( j = 0; j < server->max_fd[index] + 1; j++ ) {
                                if ( FD_ISSET(j, &server->read_fdset[index])) {
                                    FD_SET(j, &read_fdset);
                                }
                                if ( FD_ISSET(j, &server->write_fdset[index])) {
                                    FD_SET(j, &write_fdset);
                                }
                                if ( FD_ISSET(j,&server->except_fdset[index])) {
                                    FD_SET(j, &except_fdset);
                                }
                            }
                        }
                    }
                }

                if ( max_fd < 0 ) {
                    Log(LOG_ERR, "max_fd not set!\n");
                    exit(-1);
                }

                /* check how long we should be waiting for before timing out */
#if HAVE_CURL_MULTI_TIMEOUT
                //TODO: check other timeouts, currently using first, regardless
                if ( curl_multi_timeout(serverList->multi[0], &wait) ) {
                    Log(LOG_ERR, "error calling curl_multi_timeout!\n");
                    exit(-1);
                }

                /* it's polite to wait at least a short time */
                if(wait < 0)
                    wait = 1000;
#else
                wait = 1000;
#endif
                /* TODO:
                 * update timeout values if interrupted. Not too worried about
                 * this just now...
                 */
                timeout.tv_sec = wait / 1000;
                timeout.tv_usec = (wait % 1000) * 1000;

                result = select(max_fd + 1, &read_fdset, &write_fdset,
                        &except_fdset, &timeout);
            } while ( result < 0 && errno == EINTR );

            if ( result < 0 ) {
                Log(LOG_ERR, "error in select: %i (%s)\n", errno,
                        strerror(errno));
                exit(-1);
            }
        }

        /* XXX this is identical to the first block except it checks msgs */
        /* call curl_multi_perform() until it no longer wants to be run.
         * XXX thought it might be useful to round-robin it across all
         * connections, but now I'm not sure that offers any advantage over
         * dealing with each one in turn
         */
        data_outstanding = 1;
        while ( data_outstanding ) {
            running_handles = 0;
            data_outstanding = 0;
            for ( server=server_list; server != NULL; server=server->next) {
                //XXX new to force start new connections once an initial
                //response has been received
                pipeline_next_object(server);
                for ( index = 0; index < server->num_pipelines; index++) {
                    if ( server->multi[index] == NULL ) {
                        continue;
                    }
                    if ( curl_multi_perform(server->multi[index],
                                &server->running_handles[index]) ==
                            CURLM_CALL_MULTI_PERFORM ) {
                        data_outstanding = 1;
                    }
                    check_messages(server->multi[index],
                            &server->running_handles[index], index);

                    running_handles += server->running_handles[index];
                }
            }
        }
    }

    /* clean up all the connections we opened */
    for(server = server_list; server != NULL; server = server->next) {
        for ( index = 0; index < server->num_pipelines; index++ ) {
            if ( server->multi[index] != NULL ) {
                curl_multi_cleanup(server->multi[index]);
            }
        }
    }

    curl_share_cleanup(share_handle);
    return result;
}



/*
 *
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
 *
 */
static void usage(char *prog) {
    printf("Usage: %s -u <url> [OPTIONS]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -u <url>\tURL of the page to fetch\n");
    printf("  -k \t\tDisable keep-alives (def:enabled)\n");
    printf("  -m <max>\tMaximum number of connections (def:24)\n");
    printf("  -s <max>\tMaximum number of connections per server (def:8)\n");
    printf("  -x <max>\tMaximum number of persistent connections per server (def:2)\n");
    printf("  -p\t\tEnable pipelining (def:disabled)\n");
    printf("  -r <max>\tMaximum number of pipelined requests (def:4)\n");
    printf("  -z <max>\tOutstanding pipelined requests before using new pipe (def:2)\n");
    printf("  -c\t\tAllow cached content (def:false)\n");
}



/*
 * Reimplementation of the HTTP2 test from AMP
 *
 * TODO get useful errors into the log strings
 * TODO get test name into log strings
 * TODO logging will need more work - the log level won't be set.
 * TODO const up the dest arguments so cant be changed?
 */
//XXX dests should not have anything in it?
//XXX how about dests has the hostname/address and url just appends to that?
int run_http(int argc, char *argv[], __attribute__((unused))int count,
        __attribute__((unused))struct addrinfo **dests) {
    int opt;
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
    options.pipe_size_before_skip = 2;

    while ( (opt = getopt(argc, argv, "u:km:s:x:pr:cz:h")) != -1 ) {
	switch ( opt ) {
	    //case 'u': strncpy(options.url, optarg, MAX_URL_LEN); break;
	    case 'u': split_url(optarg, options.host, options.path);
                      strncpy(options.url, optarg, MAX_URL_LEN); break;
	    case 'k': options.keep_alive = 1; break;
	    case 'm': options.max_connections = atoi(optarg); break;
	    case 's': options.max_connections_per_server = atoi(optarg); break;
	    case 'x': options.max_persistent_connections_per_server =
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
            case 'r': options.pipelining_maxrequests = atoi(optarg); break;
            case 'c': options.caching = 1; break;
            case 'z': options.pipe_size_before_skip = atoi(optarg); break;
	    case 'h':
	    default: usage(argv[0]); exit(0);
	};
    }

    configure_global_max_requests(&options);

    if ( gettimeofday(&global.start, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(-1);
    }

    curl_global_init(CURL_GLOBAL_ALL);
    fetch(options.url);
    curl_global_cleanup();

    if ( gettimeofday(&global.end, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(-1);
    }

    /* send report */
    report_results(&global.start, server_list, &options);

    /* TODO, free everything */
    //free(server_list);

    return 0;
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_HTTP;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("http");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 300;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_http;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_http;

    return new_test;
}
