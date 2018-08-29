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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "http.h"
#include "servers.h"
#include "parsers.h"
#include "debug.h"

extern struct server_stats_t *server_list;
extern struct opt_t options;

/*
 * Don't do anything with the objects that we fetch to make up the page.
 */
size_t do_nothing(__attribute__((unused))void *ptr, size_t size,
        size_t nmemb, __attribute__((unused))void *data) {
    return size * nmemb;
}



/*
 * Record the cache control headers that were present in the response.
 * Currently checks for
 *
 *      Cache-Control:  public private no-cache no-store no-transform
 *                      must-revalidate proxy-revalidate max-age s-maxage
 *
 *      X-Cache: HIT MISS
 *      X-Cache-Lookup: HIT MISS
 */
size_t parse_headers(void *ptr, size_t size, size_t nmemb, void *data) {
    struct object_stats_t *object = (struct object_stats_t *)data;
    struct cache_headers_t *cache = &object->headers;
    char *buf;

    /*
     * The header probably isn't null terminated, but probably does end with
     * CRLF. Copy the whole thing into our own buffer and add an extra null
     * byte on the end so we can be certain it's terminated without possibly
     * clobbering useful data.
     */
    buf = calloc(size, nmemb + 1);
    memcpy(buf, ptr, size * nmemb);

    /* check normal caching headers, they are usually all listed on one line */
    if ( strncasecmp(buf, "Cache-Control: ", strlen("Cache-Control: ")) == 0 ) {
        char *directives = buf + strlen("Cache-Control: ");
        char *dirptr, *token;

        /*
         * Directives should be "each separated by one or more commas (",")
         * and OPTIONAL linear white space (LWS)". Some stupid implementations
         * have also been observed using semicolons, so I guess we look for
         * them too.
         * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html
         */
        if ( (token = strtok_r(directives, " \t,;", &dirptr)) == NULL ) {
            free(buf);
            return size * nmemb;
        }

        do {
            /*
             * This is hideous but I can't think of a nicer way to do it.
             * strlen() should be used rather than a fixed value but the
             * added length turns it into an (even more) unreadable mess.
             */
            if ( strncasecmp(token, "public", 6) == 0 ) {
                cache->flags.pub = 1;
            } else if ( strncasecmp(token, "private", 7) == 0 ) {
                cache->flags.priv = 1;
            } else if ( strncasecmp(token, "no-cache", 8) == 0 ) {
                cache->flags.no_cache = 1;
            } else if ( strncasecmp(token, "no-store", 8) == 0 ) {
                cache->flags.no_store = 1;
            } else if ( strncasecmp(token, "no-transform", 12) == 0 ) {
                cache->flags.no_transform = 1;
            } else if ( strncasecmp(token, "must-revalidate", 15) == 0 ) {
                cache->flags.must_revalidate = 1;
            } else if ( strncasecmp(token, "proxy-revalidate", 16) == 0 ) {
                cache->flags.proxy_revalidate = 1;
            } else if ( strncasecmp(token, "max-age", 7) == 0 ) {
                sscanf(token, "max-age=%d", &cache->max_age);
            } else if ( strncasecmp(token, "s-maxage", 8) == 0 ) {
                sscanf(token, "s-maxage=%d", &cache->s_maxage);
            } else {
                Log(LOG_DEBUG, "skipping unknown directive: '%s'\n", token);
            }
        } while ( (token = strtok_r(NULL, " ,", &dirptr)) != NULL );

    } else if ( strncasecmp(buf, "X-Cache: ", strlen("X-Cache: ")) == 0 ) {
        char *directives = buf + strlen("X-Cache: ");

        if ( strncasecmp(directives, "HIT", strlen("HIT")) == 0 ) {
            cache->x_cache = 1;
        } else if ( strncasecmp(directives, "MISS", strlen("MISS")) == 0 ) {
            cache->x_cache = 0;
        } else {
            Log(LOG_DEBUG, "skipping unknown x-cache response: '%s'\n",
                    directives);
        }

    } else if(strncasecmp(buf,"X-Cache-Lookup: ",strlen("X-Cache-Lookup: ")) == 0) {
        char *directives = buf + strlen("X-Cache-Lookup: ");

        if ( strncasecmp(directives, "HIT", strlen("HIT")) == 0 ) {
            cache->x_cache_lookup = 1;
        } else if ( strncasecmp(directives, "MISS", strlen("MISS")) == 0 ) {
            cache->x_cache_lookup = 0;
        } else {
            Log(LOG_DEBUG, "skipping unknown x-cache response: '%s'\n",
                    directives);
        }

    } else if (strncmp(buf,"HTTP/1.0 200 OK",strlen("HTTP/1.0 200 OK")) == 0) {
        /* we might get a "Connection: keep-alive" header here, but we won't
         * be able to do pipelining over a HTTP/1.0 connection, so limit it
         * to 1 outstanding request
         */
        struct server_stats_t *server;
        get_server(object->server_name, server_list, &server);
        if ( options.pipelining ) {//XXX global now...
            server->pipelining_maxrequests = 1;
        }

    } else if (strncmp(buf,"HTTP/1.1 200 OK",strlen("HTTP/1.1 200 OK")) == 0) {
        /* every HTTP/1.1 connection should be able to do pipelining, lets
         * take that gamble
         */
        struct server_stats_t *server;
        get_server(object->server_name, server_list, &server);
        if ( options.pipelining ) {//XXX global now...
            server->pipelining_maxrequests = options.pipelining_maxrequests;
        }

    } else if ( strncasecmp(buf, "Location: ", strlen("Location: ")) == 0 ) {
        /*
         * Make a copy of the location header so we can redirect there after
         * reporting that this initial object returned a redirect. If we just
         * used the curl functionality with CURLOPT_FOLLOWLOCATION then it
         * would hide this and we wouldn't know the redirect took place and it
         * wouldn't show up as a separate object.
         */
        char location[MAX_URL_LEN];
        sscanf(buf, "%*[Ll]ocation: %s", (char*)&location);
        object->location = strdup(location);
    } else {
        Log(LOG_DEBUG, "ignored header: %s\n", buf);
    }

    free(buf);
    return size * nmemb;
}



/*
 * Walk through the buffer looking for any external resources that we should
 * also download to complete the page. Anything pointed to by "src=" inside
 * of <script> and <img> tags, or "href=" inside of <link> will be fetched.
 *
 * Check lexer.l to see how they are extracted from the page source.
 */
size_t parse_response(void *ptr, size_t size, size_t nmemb, void *data) {
    int pipefd[2];
    FILE *writer;
    int written = 0;
    int total = size * nmemb;
    extern FILE *yyin;
    int yylex(void);

    if ( pipe(pipefd) == -1 ) {
        Log(LOG_ERR, "error creating pipe\n");
        exit(EXIT_FAILURE);
    }

    /* open a pipe for writing data to the lexer */
    fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
    if ( (writer = fdopen(pipefd[1], "w")) == NULL ) {
        Log(LOG_ERR, "error opening pipe for writing: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    /* open pipe for reading data into the lexer */
    if ( (yyin = fdopen(pipefd[0], "r")) == NULL ) {
        Log(LOG_ERR, "error opening pipe for reading: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    /*
     * Send everything curl gave us on to the lexer, which will create objects
     * and queue them as it finds them
     */
    do {
        written += fwrite(ptr, size, nmemb, (FILE*)writer);

        if ( written < total ) {
            if ( ferror(writer) && errno != EAGAIN ) {
                /* breaking here will return < total, which will error */
                fclose(writer);
                writer = NULL;
                break;
            }
        }

        /* finished, make sure all the data has got through */
        if ( written == total) {
            fflush(writer);
            fclose(writer);
            writer = NULL;
        }

        yylex();
    } while ( !ferror(data) && written < total );

    fclose(yyin);

    return written;
}
