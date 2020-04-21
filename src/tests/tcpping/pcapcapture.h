/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Shane Alcock
 *         Brendon Jones
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

#ifndef _TCPPING_PCAPCAPTURE_H_
#define _TCPPING_PCAPCAPTURE_H_

#include <pcap.h>
#include <event2/event.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdint.h>
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
    struct event *event;
    struct pcapdevice *next;
};

struct pcaptransport {
    char *header;
    uint8_t protocol;
    int remaining;
    struct timeval ts;
};

void pcap_cleanup(void);

int pcap_listen(struct sockaddr *address, uint16_t srcportv4,
        uint16_t srcportv6, uint16_t destport, char *device,
        struct event_base *base,
        void *callbackdata,
        void(*callback)(evutil_socket_t evsock, short flags, void *evdata));

int find_source_address(char *device, struct addrinfo *dest,
        struct sockaddr *saddr);
struct pcaptransport pcap_transport_header(struct pcapdevice *p);

#endif

/* vim: set sw=4 tabstop=4 softtabstop=4 expandtab : */

