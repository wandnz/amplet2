/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2022 The University of Waikato, Hamilton, New Zealand.
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


#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

#include "config.h"
#include "locator.h"
#include "getinmemory.h"
#include "debug.h"

#define JSON_STRING(json, name) (json_string_value(json_object_get(json, name)))

/*
 * Locate response is json, in the following format:
 *
 * {
 *   results: [
 *     {
 *       machine: "mlab1-akl01.mlab-oti.measurement-lab.org",
 *       location: {
 *         city: "Auckland",
 *         country: "New Zealand"
 *       },
 *       urls: {
 *         ws:///ndt/v7/download: "ws://ndt-mlab1-akl01...",
 *         ws:///ndt/v7/upload: "ws://ndt-mlab1-akl01...",
 *         wss:///ndt/v7/download: "wss://ndt-mlab1-akl01...",
 *         wss:///ndt/v7/upload: "wss://ndt-mlab1-akl01...",
 *       },
 *     },
 *     ...
 *   ]
 */
static struct target *parse_locate(struct MemoryStruct chunk) {
    json_error_t error;
    json_auto_t *root;
    json_t *results;
    struct target *targets;

    root = json_loadb(chunk.memory, chunk.size, 0, &error);
    if ( !root ) {
        Log(LOG_WARNING,
                "Error decoding json (line %d: %s)", error.line, error.text);
        return NULL;
    }

    results = json_object_get(root, "results");
    if ( !results || !json_is_array(results) ) {
        Log(LOG_WARNING, "Missing results array");
        return NULL;
    }

    /* enough space for all targets, plus one empty one to terminate */
    targets = calloc(json_array_size(results) + 1, sizeof(struct target));

    size_t i;
    json_t *value;

    json_array_foreach(results, i, value) {
        json_t *urls;
        json_t *location;

        /* TODO better error checking around the json response */
        targets[i].machine = strdup(JSON_STRING(value, "machine"));

        location = json_object_get(value, "location");
        targets[i].city = strdup(JSON_STRING(location, "city"));
        targets[i].country = strdup(JSON_STRING(location, "country"));

        urls = json_object_get(value, "urls");
        if ( !json_is_object(urls) ) {
            Log(LOG_WARNING, "No ndt service urls");
            return NULL;
        }

        /* TODO warn if there aren't 4 urls or data format is different? */
        targets[i].urls[0] = strdup(JSON_STRING(urls, "ws:///ndt/v7/download"));
        targets[i].urls[1] = strdup(JSON_STRING(urls, "ws:///ndt/v7/upload"));
        targets[i].urls[2] = strdup(JSON_STRING(urls, "wss:///ndt/v7/download"));
        targets[i].urls[3] = strdup(JSON_STRING(urls, "wss:///ndt/v7/upload"));
    }

    return targets;
}



/*
 * Load the locator page to find our target endpoint
 */
struct target *locate(void/*char *scheme, char *service*/) {
    CURL *curl;
    struct MemoryStruct chunk;
    struct target *targets;

    chunk.memory = malloc(1);
    chunk.size = 0;
    targets = NULL;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if ( curl ) {
        CURLcode res;

        curl_easy_setopt(curl, CURLOPT_URL, NDT_LOCATE_URL);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        Log(LOG_DEBUG, "Querying location service: " NDT_LOCATE_URL);

        res = curl_easy_perform(curl);
        if ( res == CURLE_OK ) {
            long code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            Log(LOG_DEBUG, "Response code %d", code);
            /* only run the test on a 200 response, 204 means no capacity */
            if ( code == 200 ) {
                targets = parse_locate(chunk);
            }
        }

        curl_easy_cleanup(curl);
    }

    free(chunk.memory);
    curl_global_cleanup();

    return targets;
}
