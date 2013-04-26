#ifndef _TESTS_HTTP_SERVERS_H
#define _TESTS_HTTP_SERVERS_H

#include "http.h"

struct server_stats_t *get_server(char *name,
        struct server_stats_t *server, struct server_stats_t **result);

#endif
