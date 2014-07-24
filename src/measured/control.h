#ifndef _MEASURED_CONTROL_H
#define _MEASURED_CONTROL_H

#include <libwandevent.h>
#include "testlib.h"

// TODO good default values for these things
/* control port is a string that gets given to getaddrinfo() */
#define CONTROL_PORT "8869"

/* Allow the test server to run slightly longer than the client test */
#define TEST_SERVER_EXTRA_TIME 60

int initialise_control_socket(struct socket_t *sockets, char *iface,
        char *ipv4, char *ipv6, char *port);
void control_establish_callback(wand_event_handler_t *ev_hdl, int eventfd,
        __attribute__((unused))void *data,
        __attribute__((unused))enum wand_eventtype_t ev);

#endif
