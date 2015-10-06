#include <malloc.h>
#include <string.h>
#include <assert.h>

#include "http.h"
#include "servers.h"

extern int total_pipelines;

/*
 *
 */
static struct server_stats_t *create_server(char *name, int pipelines) {
    struct server_stats_t *server =
        (struct server_stats_t*)malloc(sizeof(struct server_stats_t));
    int i;

    memset(server, 0, sizeof(struct server_stats_t));
    strncpy(server->server_name, name, MAX_DNS_NAME_LEN);
    strcpy(server->address, "0.0.0.0");

    server->pipelining_maxrequests = 1;
    server->pipelines = malloc(pipelines * sizeof(struct object_stats_t*));
    server->pipelen = malloc(pipelines * sizeof(int));
    server->num_pipelines = pipelines;

    for ( i = 0; i < pipelines; i++ ) {
        server->pipelines[i] = NULL;
        server->pipelen[i] = 0;
    }

    global.servers++;

    return server;
}



/*
 * Try to find the given server name in the server list. If it is not found
 * then it should be created. Regardless, the (possibly updated) server list
 * is returned and a reference to the particular server is stored in result.
 */
struct server_stats_t *get_server(char *name,
        struct server_stats_t *server, struct server_stats_t **result) {

    assert(name);
    assert(result);

    /* the server list is empty, create the server and return it as the list */
    if ( server == NULL ) {
        *result = create_server(name, total_pipelines);
        return *result;
    }

    /* this is the server we were after */
    if ( strcmp(name, server->server_name) == 0 ) {
        *result = server;
        return server;
    }

    /* keep looking down the list */
    server->next = get_server(name, server->next, result);
    return server;
}
