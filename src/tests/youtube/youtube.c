/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2022 The University of Waikato, Hamilton, New Zealand.
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
#include <assert.h>
#include <string.h>
#include <libwebsockets.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <jansson.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/prctl.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "youtube.h"
#include "youtube.pb-c.h"
#include "getinmemory.h"
#include "debug.h"
#include "dscp.h"
#include "usage.h"


// move these into websocket user storage?
struct command *outqueue = NULL;
int outstanding = 0;

// TODO add option to find best quality it can run without buffering?
// is that still possible or can you no longer select quality?
static struct option long_options[] = {
    {"quality", required_argument, 0, 'q'},
    {"useragent", required_argument, 0, 'a'},
    {"user-agent", required_argument, 0, 'a'},
    {"no-browser", no_argument, 0, 'b'},
    {"port", required_argument, 0, 'P'},
    {"youtube", required_argument, 0, 'y'},
    {"max-runtime", required_argument, 0, 't'},
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

static struct lws *wsi_yt = NULL;
static volatile int force_exit = 0;



/*
 * Check that the quality string matches a known video quality value.
 */
static int validate_quality(char *quality) {
    if ( quality == NULL ||
            strcmp(quality, "default") == 0 ||
            strcmp(quality, "small") == 0 ||
            strcmp(quality, "medium") == 0 ||
            strcmp(quality, "large") == 0 ||
            strcmp(quality, "hd720") == 0 ||
            strcmp(quality, "hd1080") == 0 ||
            strcmp(quality, "hd1440") == 0 ||
            strcmp(quality, "hd2160") == 0 ||
            strcmp(quality, "highres") == 0 ) {
        return 0;
    }

    return -1;
}



/*
 * Convert a quality string into the enum value.
 */
static Amplet2__Youtube__Quality parse_quality(const char *quality) {
    if ( quality == NULL || strcmp(quality, "default") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__DEFAULT;
    }

    if ( strcmp(quality, "small") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__SMALL;
    } else if ( strcmp(quality, "medium") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__MEDIUM;
    } else if ( strcmp(quality, "large") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__LARGE;
    } else if ( strcmp(quality, "hd720") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD720;
    } else if ( strcmp(quality, "hd1080") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD1080;
    } else if ( strcmp(quality, "hd1440") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD1440;
    } else if ( strcmp(quality, "hd2160") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HD2160;
    } else if ( strcmp(quality, "highres") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__HIGHRES;
    } else if ( strcmp(quality, "unknown") == 0 ) {
        return AMPLET2__YOUTUBE__QUALITY__UNKNOWN;
    }

    Log(LOG_WARNING, "Unknown quality '%s'", quality);
    return AMPLET2__YOUTUBE__QUALITY__UNKNOWN;
}



/*
 * Convert the video quality enum into a printable string.
 */
static char* get_quality_string(Amplet2__Youtube__Quality quality) {
    switch ( quality ) {
        case AMPLET2__YOUTUBE__QUALITY__DEFAULT: return "default";
        case AMPLET2__YOUTUBE__QUALITY__SMALL: return "small";
        case AMPLET2__YOUTUBE__QUALITY__MEDIUM: return "medium";
        case AMPLET2__YOUTUBE__QUALITY__LARGE: return "large";
        case AMPLET2__YOUTUBE__QUALITY__HD720: return "hd720";
        case AMPLET2__YOUTUBE__QUALITY__HD1080: return "hd1080";
        case AMPLET2__YOUTUBE__QUALITY__HD1440: return "hd1440";
        case AMPLET2__YOUTUBE__QUALITY__HD2160: return "hd2160";
        case AMPLET2__YOUTUBE__QUALITY__HIGHRES: return "highres";
        default: return "unknown";
    };
}



/*
 * Convert an event type string into the enum value.
 */
static Amplet2__Youtube__EventType parse_timeline_event(const char *event) {
    if ( strcmp(event, "ready") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__READY;
    } else if ( strcmp(event, "unstarted") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__UNSTARTED;
    } else if ( strcmp(event, "buffering") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__BUFFERING;
    } else if ( strcmp(event, "quality") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY;
    } else if ( strcmp(event, "playing") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__PLAYING;
    } else if ( strcmp(event, "ended") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__ENDED;
    } else if ( strcmp(event, "error") == 0 ) {
        return AMPLET2__YOUTUBE__EVENT_TYPE__ERROR;
    }

    Log(LOG_WARNING, "Unknown event '%s'", event);
    return AMPLET2__YOUTUBE__EVENT_TYPE__UNKNOWN_EVENT;
}



/*
 * Convert the event type enum into a printable string.
 */
static char* get_event_string(Amplet2__Youtube__EventType event) {
    switch ( event ) {
        case AMPLET2__YOUTUBE__EVENT_TYPE__READY: return "ready";
        case AMPLET2__YOUTUBE__EVENT_TYPE__UNSTARTED: return "unstarted";
        case AMPLET2__YOUTUBE__EVENT_TYPE__BUFFERING: return "buffering";
        case AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY: return "quality change";
        case AMPLET2__YOUTUBE__EVENT_TYPE__PLAYING: return "playing";
        case AMPLET2__YOUTUBE__EVENT_TYPE__ENDED: return "ended";
        case AMPLET2__YOUTUBE__EVENT_TYPE__ERROR: return "error";
        default: return "unknown";
    };
}



/*
 * Parse the result message into the context user data.
 */
static void parse_result(struct lws *wsi, json_t *result) {
    struct YoutubeTiming *stats =
        (struct YoutubeTiming*)lws_context_user(lws_get_context(wsi));

    json_t *value = json_object_get(result, "value");

    /* copy the strings as they only exist while the json object does */
    stats->video = strdup(JSON_STR(value, "video"));
    stats->title = strdup(JSON_STR(value, "title"));

    /* add all the timing values */
    stats->quality = parse_quality(JSON_STR(value, "quality"));
    stats->initial_buffering = JSON_INT(value, "initial_buffering");
    stats->playing_time = JSON_INT(value, "playing_time");
    stats->stall_time = JSON_INT(value, "stall_time");
    stats->stall_count = JSON_INT(value, "stall_count");
    stats->total_time = JSON_INT(value, "total_time");
    stats->pre_time = JSON_INT(value, "pre_time");
    stats->reported_duration = JSON_INT(value, "reported_duration");

    json_t *timeline = json_object_get(value, "timeline");
    stats->event_count = json_array_size(timeline);

    if ( stats->event_count > 0 ) {
        size_t i;
        json_t *event;

        stats->timeline =
            calloc(stats->event_count, sizeof(struct TimelineEvent));

        /* add each timeline event to the stats array */
        json_array_foreach(timeline, i, event) {
            stats->timeline[i].timestamp = JSON_INT(event, "timestamp");
            stats->timeline[i].type =
                parse_timeline_event(JSON_STR(event, "event"));
            json_t *quality = json_object_get(event, "quality");
            if ( quality ) {
                stats->timeline[i].quality =
                    parse_quality(json_string_value(quality));
            }
        }
    }
}



/*
 * Print the event timeline.
 */
static void print_timeline_event(Amplet2__Youtube__Event *event) {
    printf("    %8" PRIu64 "ms", event->timestamp);
    printf(" %s", get_event_string(event->type));
    if ( event->type == AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY &&
            event->has_quality ) {
        printf(" (%s)", get_quality_string(event->quality));
    }
    printf("\n");
}



/*
 * Print statistics related to the video playback.
 */
static void print_video(Amplet2__Youtube__Item *video) {
    unsigned int i;

    assert(video);

    printf("  Title: \"%s\"\n", video->title);
    printf("  Final quality: %s\n", get_quality_string(video->quality));

    printf("  Reported duration: ");
    if ( video->has_reported_duration ) {
        printf("%lums\n", video->reported_duration);
    } else {
        printf("unknown\n");
    }

    printf("  Time before buffering: ");
    if ( video->has_pre_time ) {
        printf("%lums\n", video->pre_time);
    } else {
        printf("unknown\n");
    }

    printf("  Initial buffering: ");
    if ( video->has_initial_buffering ) {
        printf("%lums\n", video->initial_buffering);
    } else {
        printf("unknown\n");
    }

    printf("  Time playing: ");
    if ( video->has_playing_time ) {
        printf("%lums\n", video->playing_time);
    } else {
        printf("unknown\n");
    }

    if ( video->has_stall_count ) {
        if ( video->stall_count == 0 ) {
            printf("  Maintained continuous playback, did not stall\n");
        } else {
            printf("  Stalled %lu times for a total of %lums\n",
                    video->stall_count, video->stall_time);
        }
    }

    printf("  Total time: %lums\n", video->total_time);
    printf("  Timeline:\n");
    for ( i = 0; i < video->n_timeline; i++ ) {
        print_timeline_event(video->timeline[i]);
    }
}



/*
 * Push a command on the end of the command queue.
 */
static struct command *enqueue(struct command *queue, struct command *cmd) {
    struct command *current;

    if ( queue == NULL ) {
        return cmd;
    }

    current = queue;
    while ( current->next != NULL ) {
        current = current->next;
    }

    current->next = cmd;

    return queue;
}



/*
 * Pop a command from the front of the command queue.
 */
static struct command *dequeue(struct command *queue, struct command **cmd) {
    if ( queue == NULL ) {
        *cmd = NULL;
        return NULL;
    }

    *cmd = queue;
    return queue->next;
}



/*
 * Create a command, enqueue it, and ask the websocket if we can write.
 */
static void call(struct lws *wsi, char *method, char *params) {
    struct command *cmd = calloc(1, sizeof(struct command));

    cmd->method = strdup(method);
    if ( params ) {
        cmd->params = strdup(params);
    }

    outqueue = enqueue(outqueue, cmd);

    lws_callback_on_writable(wsi);
}



/*
 * Send a command to the browser connected websocket.
 */
static int ws_send(struct lws *wsi, struct command *cmd) {
    static int id = 1000;
    struct json_t *msg = json_object();

    Log(LOG_DEBUG, "sending %s: %s", cmd->method, cmd->params);

    /*
     * XXX do different versions of chromium user different arguments, or
     * is that old documentation? method vs command, params vs parameters
     */

    json_object_set_new(msg, "method", json_string(cmd->method));

    if ( cmd->params ) {
        struct json_t *params;
        struct json_error_t error;

        if ( (params = json_loads(cmd->params, 0, &error)) == NULL ) {
            Log(LOG_WARNING, "failed to decode parameters: '%s': %s",
                    cmd->params, error.text);
            json_decref(msg);
            return -1;
        }

        json_object_set_new(msg, "params", params);
    }

    json_object_set_new(msg, "id", json_integer(id));
    outstanding = id;
    id++;

    /* see how much space is needed to encode the message */
    size_t size = json_dumpb(msg, NULL, 0, 0);
    if ( size == 0 ) {
        Log(LOG_WARNING, "failed to determine encoded string length");
        json_decref(msg);
        return -1;
    }

    /* allocate the space and encode the message */
    char *buf = malloc(size + LWS_PRE);
    if ( json_dumpb(msg, &buf[LWS_PRE], size, 0) != size ) {
        Log(LOG_WARNING, "incomplete encoding for command");
        json_decref(msg);
        return -1;
    }

    /* send to websocket, leaving LWS_PRE bytes valid before the buffer */
    lws_write(wsi, (unsigned char *)&buf[LWS_PRE], size, LWS_WRITE_TEXT);

    free(buf);
    json_decref(msg);

    return 0;
}



/*
 * Build the URL used for testing, including which video to play.
 */
static char *build_test_url(struct test_options *options) {
    char *qualitystr = "";
    char *runtimestr = "";
    char *debugstr = "";
    char *baseurl;
    char *url;
    struct stat statbuf;

    if ( stat(AMP_EXTRA_DIRECTORY "/yt.html", &statbuf) == 0 &&
            statbuf.st_size > 0 ) {
        baseurl = "file://" AMP_EXTRA_DIRECTORY "/yt.html";
    } else {
        baseurl = "https://wand.net.nz/~brendonj/yt.html";
    }

    if ( options->quality ) {
        if ( asprintf(&qualitystr, "&quality=%s", options->quality) < 0 ) {
            Log(LOG_WARNING, "Failed to build quality string, aborting");
            exit(EXIT_FAILURE);
        }
    }

    if ( options->maxruntime ) {
        if ( asprintf(&runtimestr, "&runtime=%d", options->maxruntime) < 0 ) {
            Log(LOG_WARNING, "Failed to build runtime string, aborting");
            exit(EXIT_FAILURE);
        }
    }

    if ( log_level == LOG_DEBUG ) {
        debugstr = "&debug=true";
    }

    if ( asprintf(&url, "{\"url\": \"%s?video=%s%s%s%s\"}", baseurl,
                options->video, qualitystr, runtimestr, debugstr) < 0 ) {
        Log(LOG_WARNING, "Failed to build URL, aborting");
        exit(EXIT_FAILURE);
    }

    if ( options->quality ) {
        free(qualitystr);
    }

    if ( options->maxruntime ) {
        free(runtimestr);
    }

    return url;
}



/*
 * Check if the json message is informing about a javascript dialog event.
 */
static int is_javascript_dialog(json_t *root) {
    if ( strcmp(JSON_STR(root, "method"),
                "Page.javascriptDialogOpening") == 0 ) {
        return 1;
    }

    return 0;
}



/*
 * Check if the json message is informing about an inspector detached event.
 */
static int is_detach_event(json_t *root) {
    if ( strcmp(JSON_STR(root, "method"), "Inspector.detached") == 0 ) {
        return 1;
    }

    return 0;
}



/*
 * Websocket callback for connection state changes.
 */
static int callback_youtube(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len) {

    switch (reason) {
        /* earliest time we can work with the created wsi */
        case LWS_CALLBACK_WSI_CREATE: {
            Log(LOG_DEBUG, "LWS_CALLBACK_WSI_CREATE");
            break;
        }

        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_ESTABLISHED");
            struct test_options *options = (struct test_options*)user;
            char *urlparam = build_test_url(options);

            // TODO do i need to activate tab?
            //call(wsi, "Network.enable", NULL);
            call(wsi, "Page.enable", NULL);
            if ( options->useragent ) {
                char *arg;
                if ( asprintf(&arg, "{\"userAgent\": \"%s\"}",
                            options->useragent) < 0 ) {
                    Log(LOG_WARNING, "Failed to build useragent argument");
                    return -1;
                }
                call(wsi, "Network.setUserAgentOverride", arg);
                free(arg);
            }
            call(wsi, "Runtime.evaluate", "{\"expression\": \"navigator.userAgent\",\"returnByValue\": true}");
            call(wsi, "Page.navigate", urlparam);
            free(urlparam);
            break;
        }

        case LWS_CALLBACK_CLOSED: {
            Log(LOG_DEBUG, "LWS_CALLBACK_CLOSED");
            wsi_yt = NULL;
            force_exit = 1;
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_RECEIVE");
            int binary = lws_frame_is_binary(wsi);

            if ( !binary ) {
                ((char *)in)[len] = '\0';
                Log(LOG_DEBUG, "rx '%.*s'\n", (int)len, (char *)in);

                /* read response */
                json_t *root;
                json_error_t json_error;
                root = json_loadb((char *)in, (int)len, 0, &json_error);
                if ( !root ) {
                    Log(LOG_WARNING, "error parsing json response");
                    return -1;
                }

                /* check for error in response */
                json_t *error = json_object_get(root, "error");
                if ( error ) {
                    Log(LOG_WARNING, "%s", JSON_STR(error, "message"));
                    json_decref(root);
                    return -1;
                }

                /* check if is expected message in response to ours */
                json_t *id = json_object_get(root, "id");
                if ( !id ) {
                    /* no id, so not a response. See if it's an alert */
                    if ( is_javascript_dialog(root) ) {
                        /* handle alert and ask for results */
                        call(wsi, "Page.handleJavaScriptDialog", "{\"accept\": true}");
                        call(wsi, "Runtime.evaluate", "{\"expression\": \"youtuberesults\", \"returnByValue\": true}");
                    } else if ( is_detach_event(root) ) {
                        Log(LOG_DEBUG, "Inspector detached, closing");
                        wsi_yt = NULL;
                        force_exit = 1;
                    }

                    json_decref(root);
                    return 0;
                }

                /* has an id, but it's not one we are expecting */
                if ( json_integer_value(id) != outstanding ) {
                    Log(LOG_DEBUG, "wrong id, got %d expected %d",
                            json_integer_value(id), outstanding);
                    json_decref(root);
                    return 0;
                }

                /* the result field should exist if it's a response */
                json_t *result = json_object_get(root, "result");
                if ( !result ) {
                    Log(LOG_DEBUG, "no result in json response");
                    json_decref(root);
                    return 0;
                }

                /* result should be empty, or contain our final result */
                json_t *result2 = json_object_get(result, "result");
                if ( result2 ) {
                    /* XXX track what message we are expecting a response to */
                    const char *type = JSON_STR(result2, "type");
                    if ( strcmp(type, "string") == 0 ) {
                        /* XXX for now, clobber options->useragent */
                        struct test_options *options =
                            (struct test_options*)user;
                        options->useragent = strdup(JSON_STR(result2, "value"));
                    } else if ( strcmp(type, "object") == 0 ) {
                        // populate the context user data with the result
                        parse_result(wsi, result2);
                        // XXX alternatively, send a GET to /json/close/<ID>
                        // as this relies on the other end sending detach msg
                        call(wsi, "Page.close", NULL);
                    }
                }

                /* queue the next command if required */
                if ( outqueue ) {
                    lws_callback_on_writable(wsi);
                }

                json_decref(root);
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            Log(LOG_DEBUG, "LWS_CALLBACK_CLIENT_WRITEABLE");

            if ( outqueue ) {
                struct command *cmd;
                outqueue = dequeue(outqueue, &cmd);

                if ( cmd ) {
                    int res = ws_send(wsi, cmd);
                    if ( cmd->params ) {
                        free(cmd->params);
                    }
                    if ( res < 0 ) {
                        wsi_yt = NULL;
                        force_exit = 1;
                    }
                    free(cmd->method);
                    free(cmd);
                    return res;
                }
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            Log(LOG_WARNING, "LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
            wsi_yt = NULL;
            force_exit = 1;
            if ( in ) {
                printf("ERROR: %.*s\n", (int)len, (char*)in);
            }
            break;
        }

        default:
            break;
    }

    return 0;
}



/*
 * Extract the websocket URL from the tab creation response message.
 */
static char *parse_tab_response(struct MemoryStruct chunk) {
    json_error_t error;
    json_t *root, *ws_url;
    char *location;

    Log(LOG_DEBUG, "Parse tab response: %.*s", chunk.size, chunk.memory);

    root = json_loadb(chunk.memory, chunk.size, 0, &error);
    if ( !root ) {
        Log(LOG_WARNING,
                "Error decoding json (line %d: %s)", error.line, error.text);
        return NULL;
    }

    ws_url = json_object_get(root, "webSocketDebuggerUrl");
    if ( !ws_url || !json_is_string(ws_url) ) {
        Log(LOG_WARNING, "Missing websocket url");
        json_decref(root);
        return NULL;
    }

    /* the string value is only valid while wss exists, so make our own copy */
    location = strdup(json_string_value(ws_url));
    json_decref(root);

    return location;
}



/*
 * Create a new browser tab and return its websocket URL.
 */
static char *new_browser_tab(char *dev_url) {
    CURL *curl;
    char *url;
    char *location;
    struct MemoryStruct chunk;

    location = NULL;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if ( curl ) {
        CURLcode res;
        int attempts = 0;

        /* GET this endpoint to open a new tab */
        if ( asprintf(&url, "%s/json/new", dev_url) < 0 ) {
            Log(LOG_WARNING, "Failed to create new browser tab url");
            return NULL;
        }

        Log(LOG_DEBUG, "URL: %s", url);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        Log(LOG_DEBUG, "Trying to connect to browser");
        while ( (res = curl_easy_perform(curl)) == CURLE_COULDNT_CONNECT &&
                attempts < MAX_RETRY_ATTEMPTS ) {
            Log(LOG_DEBUG, "Couldn't connect to browser, will retry");
            sleep(1 << attempts);
            attempts++;
        }

        if ( res == CURLE_OK ) {
            Log(LOG_DEBUG, "Connected to browser ok");
            /* response includes websocket location to interact with tab */
            location = parse_tab_response(chunk);
        } else {
            Log(LOG_WARNING, "Error opening new browser tab: %s",
                    curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        free(url);
    }

    free(chunk.memory);
    curl_global_cleanup();

    Log(LOG_DEBUG, "Got browser tab websocket location: %s", location);

    return location;
}



/*
 * Build a connect info struct, including URL for the web socket.
 */
static struct lws_client_connect_info* build_lws_connect_info(
        char *url, struct lws_context *context, struct test_options *options) {

    struct lws_client_connect_info *info;
    const char *scheme, *p;
    char path[300];

    //Log(LOG_DEBUG, "Original URL: %s", url);

    info = calloc(1, sizeof(struct lws_client_connect_info));

    //if ( lws_parse_uri(url, &prot, &i.address, &i.port, &i.path) ) {
    if ( lws_parse_uri(url, &scheme, &info->address, &info->port, &p) ) {
        Log(LOG_WARNING, "XXX failed to parse?");
        free(info);
        return NULL;
    }

    //Log(LOG_DEBUG, "Parsed URL, address:%s path:%s", info->address, p);

    // XXX look into this path? the GET is missing the leading slash
    /* add back the leading / on path */
    path[0] = '/';
    strncpy(path + 1, p, sizeof(path) - 2);
    path[sizeof(path) - 1] = '\0';
    info->path = strdup(path);

    //Log(LOG_DEBUG, "Fixed URL, address:%s path:%s", info->address, info->path);

    info->context = context;
    info->host = info->address;
    info->origin = info->address;
    info->ietf_version_or_minus_one = -1;

    // use this pointer instead of having it automatically allocated
    info->userdata = options;

    Log(LOG_DEBUG, "address:%s path:%s", info->address, info->path);
    Log(LOG_DEBUG, "scheme:%s port:%d", scheme, info->port);

    return info;
}



/*
 * Build websocket context info, and set appropriate callbacks.
 */
static struct lws_context_creation_info* build_lws_context_info(void) {
    struct lws_context_creation_info *info;
    struct lws_protocols *protocols;

    protocols = calloc(2, sizeof(struct lws_protocols));
    protocols[0].callback = callback_youtube;
    protocols[0].rx_buffer_size = 8192;
    protocols[0].name = "devtools";

    info = calloc(1, sizeof(struct lws_context_creation_info));
    info->port = CONTEXT_PORT_NO_LISTEN;
    info->protocols = protocols;
    info->gid = -1;
    info->uid = -1;
    info->vhost_name = "127.0.0.1";
    info->user = calloc(1, sizeof(struct YoutubeTiming));

    return info;
}



/*
 * Construct a protocol buffer message containing the timeline of events that
 * took place during the video download and playback.
 */
static Amplet2__Youtube__Event* report_timeline_event(
        struct TimelineEvent *info) {
    Amplet2__Youtube__Event *event =
        (Amplet2__Youtube__Event*)malloc(sizeof(Amplet2__Youtube__Event));

    assert(info);
    assert(event);

    amplet2__youtube__event__init(event);
    event->has_timestamp = 1;
    event->timestamp = info->timestamp;
    event->has_type = 1;
    event->type = info->type;

    if ( event->type == AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY ) {
        event->has_quality = 1;
        event->quality = info->quality;
    }

    return event;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for the youtube video
 */
static amp_test_result_t* report_results(struct timeval *start_time,
        struct YoutubeTiming *stats, struct test_options *opt) {

    unsigned int i;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Amplet2__Youtube__Report msg = AMPLET2__YOUTUBE__REPORT__INIT;
    Amplet2__Youtube__Header header = AMPLET2__YOUTUBE__HEADER__INIT;
    Amplet2__Youtube__Item video = AMPLET2__YOUTUBE__ITEM__INIT;

    header.video = opt->video;
    header.quality = parse_quality(opt->quality);
    header.has_quality = 1;
    header.dscp = opt->dscp;
    header.has_dscp = 1;
    header.useragent = opt->useragent;
    header.has_maxruntime = 1;
    header.maxruntime = opt->maxruntime;

    video.title = stats->title;
    video.has_quality = 1;
    video.quality = stats->quality;
    video.has_total_time = 1;
    video.total_time = stats->total_time;
    video.has_pre_time = 1;
    video.pre_time = stats->pre_time;

    /*
     * If initial buffering is zero it likely means the video had an error
     * before it started playing, so these values don't make sense to report.
     * TODO We might be able to assume that either the time it transitioned
     * to "unstarted" or "error" is the end of initial buffering.
     */
    if ( stats->initial_buffering > 0 ) {
        video.has_initial_buffering = 1;
        video.initial_buffering = stats->initial_buffering;
        video.has_playing_time = 1;
        video.playing_time = stats->playing_time;
        video.has_stall_time = 1;
        video.stall_time = stats->stall_time;
        video.has_stall_count = 1;
        video.stall_count = stats->stall_count;
        video.has_reported_duration = 1;
        video.reported_duration = stats->reported_duration;
    }

    /* build up the repeated timeline section */
    video.n_timeline = stats->event_count;
    video.timeline = (Amplet2__Youtube__Event **)
        malloc(sizeof(Amplet2__Youtube__Event*) * stats->event_count);

    for ( i = 0; i < video.n_timeline; i++ ) {
        video.timeline[i] = report_timeline_event(&stats->timeline[i]);
    }

    msg.item = &video;

    /* populate the top level report object with the header and servers */
    msg.header = &header;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__youtube__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__youtube__report__pack(&msg, result->data);

    for ( i = 0; i < video.n_timeline; i++ ) {
        free(video.timeline[i]);
    }
    free(video.timeline);

    return result;
}



/*
 * Try to run a chromium-browser that we can drive remotely.
 * TODO allow user to add arbitrary arguments?
 */
static pid_t start_browser(int port, int debug) {
    pid_t pid;
    char *portstr;
    char **chromium;
    char *argv[] = {
        "chromium",
        "--headless",
        "--no-sandbox",
        "--disable-dev-shm",
        "--mute-audio",
        NULL,
        NULL
    };

    /* check that we can find and run the browser executable */
    for ( chromium = chrome_paths; *chromium != NULL; chromium++ ) {
        Log(LOG_DEBUG, "Checking for browser at: %s", *chromium);
        if ( access(*chromium, X_OK) == 0 ) {
            Log(LOG_DEBUG, "Found browser at: %s", *chromium);
            break;
        }
    }

    if ( !*chromium ) {
        Log(LOG_WARNING, "Can't find browser");
        exit(EXIT_FAILURE);
    }

    /* build the remote debugging port argument, as it is user configured */
    if ( asprintf(&portstr, "--remote-debugging-port=%d", port) < 0 ) {
        Log(LOG_WARNING, "Can't build port string");
        exit(EXIT_FAILURE);
    }

    /* add it to the argument list */
    argv[5] = portstr;

    pid = fork();
    if ( pid == 0 ) {
        /* hide a bunch of warnings and errors from chromium */
        if ( !debug ) {
            fclose(stdout);
            fclose(stderr);
        }

        /* make sure the browser gets stopped when the parent stops */
        if ( prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 ) {
            Log(LOG_WARNING, "Failed to set PR_SET_PDEATHSIG");
            exit(EXIT_FAILURE);
        }

        /*
         * check that the hasn't stopped before setting PR_SET_DEATHSIG
         * (in which case we've probably been reparented to the init process)
         */
        if ( getppid() == 1 ) {
            Log(LOG_WARNING, "Test exited unexpectedly, don't start browser");
            exit(EXIT_FAILURE);
        }

        /* finally start the browser */
        if ( execv(*chromium, argv) < 0 ) {
            Log(LOG_WARNING, "Failed to start browser: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    } else if ( pid == -1 ) {
        Log(LOG_WARNING, "Failed to start browser: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    Log(LOG_DEBUG, "Browser pid: %d", pid);

    free(portstr);

    return pid;
}



/*
 * Stop the web browser. Not required in Linux due to using PR_SET_PDEATHSIG.
 */
#if 0
static void stop_browser(pid_t pid) {
    int attempts = 0;

    /* check if browser is even running */
    if ( kill(pid, 0) < 0 ) {
        Log(LOG_DEBUG, "Browser already stopped, skipping");
        return;
    }

    /* if it is, ask it nicely to terminate */
    Log(LOG_DEBUG, "Sending SIGTERM to browser pid %d", pid);
    if ( kill(pid, SIGTERM) < 0 ) {
        Log(LOG_WARNING, "Stopping browser failed: %s", strerror(errno));
        return;
    }

    /* wait for the process to die */
    while ( waitpid(pid, NULL, WNOHANG) == 0 && attempts < 5 ) {
        Log(LOG_DEBUG, "Waiting for browser to stop...");
        attempts++;
        sleep(1);
    }

    /* kill it harder if it hasn't stopped yet */
    if ( kill(pid, 0) == 0 ) {
        Log(LOG_DEBUG, "Sending SIGKILL to browser pid %d", pid);
        if ( kill(pid, SIGKILL) < 0 ) {
            Log(LOG_WARNING, "Stopping browser failed: %s", strerror(errno));
            return;
        }
    }
}
#endif



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
        "Usage: amp-youtube [-bhx] [-Q codepoint] [-Z interpacketgap]\n"
        "                   [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
        "                   [-a useragent] [-P port] [-t max-runtime]\n"
        "                   [-q quality] -y video_id\n"
        "\n");

    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --useragent     <useragent> "
            "Override browser User-Agent string\n");
    fprintf(stderr, "  -b, --no-browser           "
            "Don't start a web browser\n");
    fprintf(stderr, "  -P, --port          <port> "
            "Set remote-debugging-port (default %d)\n",
            DEFAULT_DEVTOOLS_PORT);
    fprintf(stderr, "  -q, --quality       <quality>   "
                "Suggested video quality, not guaranteed\n"
                "           (default,small,medium,large,hd720,hd1080,hd1440,hd2160,highres)\n");
    fprintf(stderr, "  -t, --max-runtime   <seconds>  "
                "Maximum duration of video playback\n");
    fprintf(stderr, "  -y, --youtube       <video_id> "
                "Youtube video ID to fetch\n");
    print_generic_usage();
}



/*
 * Main function to run the youtube test, returning a result structure that will
 * later be printed or sent across the network.
 */
amp_test_result_t* run_youtube(int argc, char *argv[],
        __attribute__((unused))int count,
        __attribute__((unused))struct addrinfo **dests) {

    int opt;
    struct timeval start_time;
    struct addrinfo *sourcev4, *sourcev6;
    amp_test_result_t *result;
    struct test_options options;
    struct YoutubeTiming *stats = NULL;
    int attempts;

    Log(LOG_DEBUG, "Starting YOUTUBE test");

    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

    /* set some sensible defaults */
    sourcev4 = NULL;
    sourcev6 = NULL;

    memset(&options, 0, sizeof(options));
    options.run_browser = 1;
    options.port = DEFAULT_DEVTOOLS_PORT;
    //options.device = NULL;

    while ( (opt = getopt_long(argc, argv, "a:bP:q:t:Xy:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4':
            case '6':
            case 'I': /* TODO --netifs-to-ignore works the opposite way */
            case 'Q':
                Log(LOG_WARNING, "UNIMPLEMENTED OPTION '-%c'", opt);
                break;
            case 'Z': /* not used, but might be set globally */ break;
            case 'a': options.useragent = optarg; break;
            case 'b': options.run_browser = 0; break;
            case 'P': options.port = atoi(optarg); break;
            case 'q': options.quality = optarg; break;
            case 't': options.maxruntime = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
                      break;
            /* TODO there is also player.loadVideoByUrl() function, useful? */
            case 'y': options.video = optarg; break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( options.video == NULL ) {
        Log(LOG_WARNING, "Missing youtube video id!\n");
        usage();
        exit(EXIT_FAILURE);
    }

    if ( validate_quality(options.quality) < 0 ) {
        Log(LOG_WARNING, "Invalid quality value: %s\n", options.quality);
        usage();
        exit(EXIT_FAILURE);
    }

    /* delay the start by a random amount if perturbate is set */
#if 0
    if ( options.perturbate ) {
	int delay;
	delay = options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		options.perturbate, delay);
	usleep(delay);
    }
#endif

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(EXIT_FAILURE);
    }

    /* start the browser if required */
    if ( options.run_browser ) {
        start_browser(options.port, (log_level == LOG_DEBUG));
        /* the browser doesn't start instantly, give it a chance */
        sleep(1);
    }

    /* connect to the devtools port and open a new tab */
    char *remote;
    if ( asprintf(&remote, "http://127.0.0.1:%d", options.port) < 0 ) {
        Log(LOG_WARNING, "Couldn't build remote connection string");
        exit(EXIT_FAILURE);
    }

    char *ws_url;
    ws_url = new_browser_tab(remote);
    free(remote);
    if ( ws_url == NULL ) {
        Log(LOG_WARNING, "Couldn't get websocket url for new tab");
        exit(EXIT_FAILURE);
    }

    /* connect to the new tab with a websocket */
    struct lws_context_creation_info *context_info;
    struct lws_client_connect_info *connect_info;
    struct lws_context *context;
    context_info = build_lws_context_info();

    context = lws_create_context(context_info);
    if ( context == NULL ) {
        Log(LOG_WARNING, "Creating libwebsocket context failed");
        exit(EXIT_FAILURE);
    }

    connect_info = build_lws_connect_info(ws_url, context, &options);
    if ( connect_info == NULL ) {
        Log(LOG_WARNING, "Creating libwebsocket connect info failed");
        exit(EXIT_FAILURE);
    }

    attempts = 0;
    Log(LOG_DEBUG, "Connecting to %s", connect_info->address);
    while ( (wsi_yt = lws_client_connect_via_info(connect_info)) == NULL &&
            attempts < MAX_RETRY_ATTEMPTS ) {
        Log(LOG_DEBUG, "Failed to connect to %s", connect_info->address);
        sleep(1 << attempts);
        attempts++;
    }

    /* if we haven't connected, skip and report empty results */
    while ( wsi_yt && !force_exit ) {
        lws_service(context, 500);
    }

    /* send report */
    stats = lws_context_user(context);
    result = report_results(&start_time, stats, &options);

    free(ws_url);
    free((char*)connect_info->path);
    free(connect_info);
    // TODO what does context destroy actually free? what do I need to free?
    //free(context_info->protocols);
    //free(context_info);
    lws_context_destroy(context);

#if 0
    if ( options.run_browser ) {
        stop_browser(pid);
    }
#endif

    /* tidy up after ourselves */
    if ( sourcev4 ) {
        freeaddrinfo(sourcev4);
    }

    if ( sourcev6 ) {
        freeaddrinfo(sourcev6);
    }

    if ( stats ) {
        // XXX check all individual parts before freeing
        free(stats->video);
        free(stats->title);
        free(stats->timeline);
        free(stats);
    }

    return result;
}



/*
 * Print test results to stdout, nicely formatted for the standalone test.
 */
void print_youtube(amp_test_result_t *result) {
    Amplet2__Youtube__Report *msg;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__youtube__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    printf("\n");
    printf("AMP YouTube test, video: %s\n", msg->header->video);
    printf("Desired quality: %s\n", get_quality_string(msg->header->quality));
    if ( msg->header->useragent ) {
        printf("User Agent: \"%s\"\n", msg->header->useragent);
    }
    if ( msg->header->maxruntime > 0 ) {
        printf("Maximum Runtime: %u seconds\n", msg->header->maxruntime);
    }

    print_video(msg->item);

    amplet2__youtube__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_YOUTUBE;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("youtube");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 300;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_youtube;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_youtube;

    /* the youtube test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the test a SIGINT warning, partial data isn't useful */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        struct YoutubeTiming *stats, struct test_options *opt) {
    return report_results(start_time, stats, opt);
}
#endif
