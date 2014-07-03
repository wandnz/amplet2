#ifndef _MEASURED_NSSOCK_H
#define _MEASURED_NSSOCK_H

#include <unbound.h>
#include <libwandevent.h>

#define MAX_RESOLVER_SOCKET_BACKLOG 16

int initialise_resolver_socket(char *path);
void resolver_socket_event_callback(wand_event_handler_t *ev_hdl, int eventfd,
        void *data, __attribute__((unused))enum wand_eventtype_t ev);

#endif
