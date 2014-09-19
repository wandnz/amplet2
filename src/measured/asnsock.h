#ifndef _MEASURED_ASNSOCK_H
#define _MEASURED_ASNSOCK_H

#include <libwandevent.h>

#include "iptrie.h"


/* data block given to each resolving thread */
struct amp_asn_info {
    int fd;                     /* file descriptor to the test process */
    iptrie_t **trie;            /* shared ASN data (with the cache) */
    pthread_mutex_t *mutex;
};

void asn_socket_event_callback(
        __attribute__((unused))wand_event_handler_t *ev_hdl, int eventfd,
        void *data, __attribute__((unused))enum wand_eventtype_t ev);

#endif
