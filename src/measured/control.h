#ifndef _MEASURED_CONTROL_H
#define _MEASURED_CONTROL_H

#include <libwandevent.h>

#include "acl.h"

/* control port is a string that gets given to getaddrinfo() */
#define DEFAULT_AMPLET_CONTROL_PORT "8869"

/* Allow the test server to run slightly longer than the client test */
#define TEST_SERVER_EXTRA_TIME 60

typedef struct amp_control {
    int enabled;
    char *port;
    char *interface;
    char *ipv4;
    char *ipv6;
    struct acl_root *acl;
} amp_control_t;

int initialise_control_socket(wand_event_handler_t *ev_hdl,
        amp_control_t *control);

void free_control_config(amp_control_t *control);
#endif
