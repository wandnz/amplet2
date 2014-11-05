#ifndef _TCPPING_PCAPCAPTURE_H_
#define _TCPPING_PCAPCAPTURE_H_

#include <pcap.h>
#include <libwandevent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


/* lenny doesn't include this, so do it ourselves if needed */
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

struct pcapdevice {
    pcap_t *pcap;
    int pcap_fd;
    char *if_name;
    void *callbackdata;
    struct pcapdevice *next;
};

struct pcaptransport {
    char *header;
    uint8_t protocol;
    int remaining;
    struct timeval ts;
};

void pcap_cleanup(wand_event_handler_t *ev_hdl);

int pcap_listen(struct sockaddr *address, uint16_t srcportv4,
        uint16_t srcportv6, uint16_t destport, char *device,
        wand_event_handler_t *ev_hdl,
        void *callbackdata,
        void (*callback)(wand_event_handler_t *ev_hdl,
            int fd, void *data, enum wand_eventtype_t ev));

int find_source_address(char *device, struct addrinfo *dest,
        struct sockaddr *saddr);
struct pcaptransport pcap_transport_header(struct pcapdevice *p);

#endif

/* vim: set sw=4 tabstop=4 softtabstop=4 expandtab : */

