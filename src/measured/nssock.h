#ifndef _MEASURED_NSSOCK_H
#define _MEASURED_NSSOCK_H

#include <unbound.h>
#include <libwandevent.h>

#define MAX_RESOLVER_SOCKET_BACKLOG 16

int initialise_resolver_socket(char *path);
//struct ub_ctx *amp_resolver_context_init(char *servers[], int nscount,
//        char *sourcev4, char *sourcev6);
void resolver_socket_event_callback(struct wand_fdcb_t *handle,
        __attribute__((unused))enum wand_eventtype_t ev);

#endif
