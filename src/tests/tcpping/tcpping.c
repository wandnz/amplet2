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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <libwandevent.h>

#include "config.h"
#include "testlib.h"
#include "tcpping.h"
#include "pcapcapture.h"
#include "tcpping.pb-c.h"
#include "debug.h"
#include "icmpcode.h"
#include "dscp.h"
#include "usage.h"
#include "checksum.h"


static struct option long_options[] = {
    {"port", required_argument, 0, 'P'},
    {"perturbate", required_argument, 0, 'p'},
    {"random", no_argument, 0, 'r'},
    {"size", required_argument, 0, 's'},
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



/*
 * Halt the event loop in the event of a SIGINT (either sent from the terminal
 * if running standalone, or sent by the watchdog if running as part of
 * measured) and report the results that have been collected so far.
 */
static void interrupt_test(wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data) {

    Log(LOG_INFO, "Received SIGINT, halting TCPPing test");
    ev_hdl->running = false;
}



/*
 * Force the event loop to halt, so we can end the test and report the
 * results that we do have.
 */
static void halt_test(wand_event_handler_t *ev_hdl, void *evdata) {
    struct tcppingglobals *tp = (struct tcppingglobals *)evdata;

    Log(LOG_DEBUG, "Halting TCPPing test due to timeout");
    tp->losstimer = NULL;
    ev_hdl->running = false;
}



/*
 * Open the raw TCP sockets needed for this test and bind them to
 * the requested device or addresses.
 */
static int open_sockets(struct tcppingglobals *tcpping) {
    if ( (tcpping->raw_sockets.socket =
            socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        Log(LOG_WARNING, "Failed to open raw socket for IPv4 TCPPing");
    }

    if ( (tcpping->raw_sockets.socket6 =
            socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) < 0) {
        Log(LOG_WARNING, "Failed to open raw socket for IPv6 TCPPing");
    }

    if ( (tcpping->tcp_sockets.socket =
            socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        Log(LOG_WARNING, "Failed to open TCP socket for IPv4 TCPPing");
    }

    if ( (tcpping->tcp_sockets.socket6 =
            socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        Log(LOG_WARNING, "Failed to open TCP socket for IPv6 TCPPing");
    }

    if ( tcpping->raw_sockets.socket < 0 &&
                tcpping->raw_sockets.socket6 < 0 ) {
        Log(LOG_ERR, "Unable to open raw sockets, aborting test");
        return 0;
    }

    if ( tcpping->tcp_sockets.socket < 0 &&
                tcpping->tcp_sockets.socket6 < 0 ) {
        Log(LOG_ERR, "Unable to open TCP sockets, aborting test");
        return 0;
    }

    /* the raw sockets are used for sending the probes, set DSCP values */
    if ( set_dscp_socket_options(&tcpping->raw_sockets,
                tcpping->options.dscp) < 0 ) {
        Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
        return 0;
    }

    if ( tcpping->device ) {
        if ( bind_sockets_to_device(&tcpping->raw_sockets,
                tcpping->device) < 0 ) {
            Log(LOG_ERR, "Unable to bind raw sockets to device, aborting test");
            return 0;
        }

        if ( bind_sockets_to_device(&tcpping->tcp_sockets,
                    tcpping->device) < 0 ) {
            Log(LOG_ERR, "Unable to bind TCP sockets to device, aborting test");
            return 0;
        }
    } else if ( tcpping->sourcev4 || tcpping->sourcev6 ) {
        if ( bind_sockets_to_address(&tcpping->raw_sockets, tcpping->sourcev4,
                    tcpping->sourcev6) < 0 ) {
            Log(LOG_ERR,"Unable to bind raw sockets to address, aborting test");
            return 0;
        }

        if ( bind_sockets_to_address(&tcpping->tcp_sockets, tcpping->sourcev4,
                    tcpping->sourcev6) < 0 ) {
            Log(LOG_ERR,"Unable to bind TCP sockets to address, aborting test");
            return 0;
        }
    }

    return 1;
}



/*
 * Close all the sockets used for the test and free source address structures.
 */
static void close_sockets(struct tcppingglobals *tcpping) {

    if ( tcpping->tcp_sockets.socket > 0 ) {
        close(tcpping->tcp_sockets.socket);
    }

    if ( tcpping->tcp_sockets.socket6 > 0 ) {
        close(tcpping->tcp_sockets.socket6);
    }

    if ( tcpping->raw_sockets.socket > 0 ) {
        close(tcpping->raw_sockets.socket);
    }

    if ( tcpping->raw_sockets.socket6 > 0 ) {
        close(tcpping->raw_sockets.socket6);
    }

    if ( tcpping->sourcev4 ) {
        freeaddrinfo(tcpping->sourcev4);
    }

    if ( tcpping->sourcev6 ) {
        freeaddrinfo(tcpping->sourcev6);
    }
}



/*
 * Listen on our TCP sockets, which will implicitly cause them to be bound
 * and assigned random available port numbers.
 *
 * Use getsockname to find which port number each socket is bound to, so
 * we can set the correct source port in our outgoing packets and create
 * filters to only match expected responses.
 */
static int listen_source_ports(struct tcppingglobals *tcpping) {

    struct socket_t *sockets = &(tcpping->tcp_sockets);

    tcpping->sourceportv4 = 0;
    tcpping->sourceportv6 = 0;

    if ( sockets->socket >= 0 ) {
        struct sockaddr_in addr;
        socklen_t addrsize = sizeof(struct sockaddr_in);

        if ( listen(sockets->socket, 10) < 0 ) {
            Log(LOG_ERR, "Failed to listen on TCP IPv4 socket: %s",
                    strerror(errno));
            return 0;
        }

        if ( getsockname(sockets->socket, (struct sockaddr *)&addr,
                    &addrsize) < 0 ) {
            Log(LOG_ERR, "Failed to get port number for TCP IPv4 socket: %s",
                    strerror(errno));
            return 0;
        }

        tcpping->sourceportv4 = ntohs(addr.sin_port);
    }

    if ( sockets->socket6 >= 0 ) {
        struct sockaddr_in6 addr;
        socklen_t addrsize = sizeof(struct sockaddr_in6);

        if ( listen(sockets->socket6, 10) < 0 ) {
            Log(LOG_ERR, "Failed to listen on TCP IPv6 socket: %s",
                    strerror(errno));
            return 0;
        }

        if ( getsockname(sockets->socket6, (struct sockaddr *)&addr,
                    &addrsize) < 0 ) {
            Log(LOG_ERR, "Failed to get port number for TCP IPv6 socket: %s",
                    strerror(errno));
            return 0;
        }

        tcpping->sourceportv6 = ntohs(addr.sin6_port);
    }

    return 1;
}



/*
 * Process command line options and make sure that the values are within
 * sensible ranges. Fix them if they aren't.
 */
static void process_options(struct tcppingglobals *tcpping) {

    /* pick a random packet size within allowable boundaries */
    if ( tcpping->options.random ) {
        tcpping->options.packet_size = MIN_TCPPING_PROBE_LEN +
            (int)((MAX_TCPPING_PROBE_LEN - MIN_TCPPING_PROBE_LEN) *
                    (random()/(RAND_MAX+1.0)));
        Log(LOG_DEBUG, "Setting packetsize to random value: %d",
                tcpping->options.packet_size);
    }

    /* make sure that the packet size is big enough for our data */
    if ( tcpping->options.packet_size < MIN_TCPPING_PROBE_LEN ) {
        Log(LOG_WARNING, "Packet size %d too small, raising to %d bytes",
                tcpping->options.packet_size, MIN_TCPPING_PROBE_LEN);
        tcpping->options.packet_size = MIN_TCPPING_PROBE_LEN;
    }

    /* make sure it isn't too big either */
    if ( tcpping->options.packet_size > MAX_TCPPING_PROBE_LEN ) {
        Log(LOG_WARNING, "Packet size %d too large, limiting to %d bytes",
                tcpping->options.packet_size, MAX_TCPPING_PROBE_LEN);
        tcpping->options.packet_size = MAX_TCPPING_PROBE_LEN;
    }

    /* delay the start by a random amount of perturbate is set */
    if ( tcpping->options.perturbate ) {
        int delay;
        delay = tcpping->options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
        Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
                tcpping->options.perturbate, delay);
        usleep(delay);
    }
}



/*
 * Append the tcp packet to the ip pseudoheader and checksum the whole buffer.
 */
static uint16_t tcp_checksum(uint16_t *packet, uint16_t *pseudo,
        int packetlen, int pseudolen) {

    char *buffer;
    uint16_t sum;

    buffer = calloc(1, pseudolen + packetlen);
    memcpy(buffer, pseudo, pseudolen);
    memcpy(buffer + pseudolen, packet, packetlen);

    sum = checksum((uint16_t*)buffer, pseudolen + packetlen);

    free(buffer);

    return sum;
}



/*
 * Calculate and set the checksum in a given TCP header.
 */
static int set_tcp_checksum(struct tcphdr *tcp, int packet_size,
        struct sockaddr *srcaddr, struct addrinfo *destaddr) {

    struct pseudotcp_ipv4 pseudov4;
    struct pseudotcp_ipv6 pseudov6;

    char *pseudo;
    int pseudolen;

    if ( srcaddr->sa_family == AF_INET ) {
        pseudov4.saddr = ((struct sockaddr_in *)srcaddr)->sin_addr.s_addr;
        pseudov4.daddr = ((struct sockaddr_in *)destaddr->ai_addr)->sin_addr.s_addr;

        pseudov4.zero = 0;
        pseudov4.protocol = 6;
        pseudov4.length = htons(packet_size);

        pseudo = (char *)&pseudov4;
        pseudolen = sizeof(pseudov4);
    } else if ( srcaddr->sa_family == AF_INET6 ) {
        memcpy(pseudov6.saddr,
                ((struct sockaddr_in6 *)srcaddr)->sin6_addr.s6_addr,
                sizeof(struct in6_addr));
        memcpy(pseudov6.daddr,
                ((struct sockaddr_in6 *)destaddr->ai_addr)->sin6_addr.s6_addr,
                sizeof(struct in6_addr));
        pseudov6.length = htonl(packet_size);
        pseudov6.zero_1 = 0;
        pseudov6.zero_2 = 0;
        pseudov6.next = 6;

        pseudo = (char *)&pseudov6;
        pseudolen = sizeof(pseudov6);
    } else {
        Log(LOG_ERR, "Unexpected family for source address: %d",
                srcaddr->sa_family);
        return 0;
    }

    tcp->check = tcp_checksum((uint16_t *)tcp, (uint16_t *)pseudo, packet_size,
            pseudolen);

    return 1;
}



/*
 * Create a TCP SYN packet for a given destination.
 */
static int craft_tcp_syn(struct tcppingglobals *tp, char *packet,
        uint16_t srcport, int packet_size, struct sockaddr *srcaddr,
        struct addrinfo *destaddr) {

    struct tcphdr *tcp;
    struct tcpmssoption *mss;
    int headerremaining = 0;
    uint32_t *noop = NULL;

    tcp = (struct tcphdr *)packet;
    tcp->source = htons(srcport);
    tcp->dest = htons(tp->options.port);
    tcp->seq = htonl(tp->seqindex + (tp->destindex * 100));
    tcp->ack_seq = 0;

    /* Pad IPv4 packets out to match the length of a IPv6 packet with
     * the same amount of payload.
     */
    if ( srcaddr->sa_family == AF_INET ) {
        tcp->doff = 11;
        headerremaining = 5;
    } else {
        tcp->doff = 6;
        headerremaining = 0;
    }
    tcp->urg = 0;
    tcp->ack = 0;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 1;
    tcp->fin = 0;
    tcp->window = htons(6666);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    mss = (struct tcpmssoption *)(packet + sizeof(struct tcphdr));
    mss->mssopt = 2;
    mss->msssize = 4;
    mss->mssvalue = htons(536);

    /* Fill any remaining header space with NOOP options */
    noop = (uint32_t *)(packet + sizeof(struct tcphdr) +
            sizeof(struct tcpmssoption));
    while (headerremaining > 0) {
        *noop = 0x01010101;
        noop ++;
        headerremaining --;
    }

    return set_tcp_checksum(tcp, packet_size, srcaddr, destaddr);
}



/*
 * Unpack the destination ID from the sequence number offset. Each destination
 * has a sequence number 100 more than the initial one, which needs to be
 * converted back to the original ID number.
 */
static int unpack_destid(int destid, int max) {
    if ( destid < 0 || destid >= (max * 100) || destid % 100 != 0 ) {
        return -1;
    }

    return destid / 100;
}



/*
 * Given a TCP header from a response packet, find the index of the
 * test target that generated the response.
 */
static inline int match_response(struct tcppingglobals *tp,
        struct tcphdr *tcp, uint8_t istcp) {
    /*
     * TODO: should we be checking if the response came from our intended
     * target vs, say, an intermediate host in the path? It will be a bit
     * annoying to have to get the IP address of the sender to check...
     */
    int destid;

    /*
     * If this is a SYN ACK or RST, we want to compare the acknowledgement
     * with the expected seqno from our SYN. If this is an ICMP response,
     * we want to look at the sequence number because we will be looking
     * at a copy of the packet we originally sent.
     */
    if ( istcp ) {
        /*
         * RST ACK packets have been observed to ack the whole SYN packet
         * including payload, but SYN ACKS often only acknowledge 1 byte.
         * If the destid doesn't look sensible, try adjusting it by the
         * payload length. Hopefully no TCP will decide to partially
         * acknowledge the SYN payload...
         */
        int packed_destid = ntohl(tcp->ack_seq) - tp->seqindex - 1;
        destid = unpack_destid(packed_destid, tp->destcount);
        if ( destid < 0 ) {
            int payload = tp->options.packet_size - MIN_TCPPING_PROBE_LEN;
            destid = unpack_destid(packed_destid - payload, tp->destcount);
        }
    } else {
        destid = unpack_destid((ntohl(tcp->seq) - tp->seqindex), tp->destcount);
    }

    if ( destid < 0 || destid >= tp->destcount ) {
        Log(LOG_DEBUG, "Invalid destid %d, ignoring", destid);
        return -1;
    }

    if ( tp->info[destid].reply != NO_REPLY ) {
        /* Already got a reply for this SYN */
        return -1;
    }

    return destid;
}



/*
 * Process the TCP header from a response to one of our probes. Check that it
 * is actually one of ours, and then extract timing information etc.
 */
static void process_tcp_response(struct tcppingglobals *tp, struct tcphdr *tcp,
        int remaining, struct timeval ts) {

    int destid;

    if ( tcp == NULL || remaining < (int)sizeof(struct tcphdr) ) {
        Log(LOG_WARNING, "Incomplete TCP header received");
        return;
    }

    if ((destid = match_response(tp, tcp, true)) >= 0) {
        int64_t delay;

        tp->info[destid].reply = TCP_REPLY;
        tp->info[destid].replyflags = 0;

        delay = DIFF_TV_US(ts, tp->info[destid].time_sent);
        if ( delay > 0 ) {
            tp->info[destid].delay = (uint32_t)delay;
        } else {
            tp->info[destid].delay = 0;
        }

        if ( tcp->urg )
            tp->info[destid].replyflags += 0x20;
        if ( tcp->ack )
            tp->info[destid].replyflags += 0x10;
        if ( tcp->psh )
            tp->info[destid].replyflags += 0x08;
        if ( tcp->rst )
            tp->info[destid].replyflags += 0x04;
        if ( tcp->syn )
            tp->info[destid].replyflags += 0x02;
        if ( tcp->fin )
            tp->info[destid].replyflags += 0x01;

        tp->outstanding --;
    }
}



/*
 * Process the ICMPv4 header from a response to one of our probes. Check that
 * it is actually one of ours, and then extract timing information etc.
 *
 * Note that I'm avoiding logging "warnings" as we will end up processing
 * every ICMP packet that matches our filter so we don't need to be
 * filling up our logs with warnings about all the other ICMP traffic
 * that our amp monitor is doing.
 */
static void process_icmp4_response(struct tcppingglobals *tp,
        struct icmphdr *icmp, int remaining, struct timeval ts) {

    char *packet = (char *)icmp;
    int destid;
    struct iphdr *ip;

    /*
     * Have to find the original TCP header to try and match this response
     * back to an outgoing SYN
     */
    if ( remaining < (int)sizeof(struct icmphdr) ) {
         return;
    }

    packet += sizeof(struct icmphdr);
    remaining -= sizeof(struct icmphdr);

    if ( remaining < (int)sizeof(struct iphdr) ) {
        return;
    }

    ip = (struct iphdr *)packet;
    if ( remaining < (ip->ihl << 2) ) {
        return;
    }

    remaining -= (ip->ihl << 2);
    packet += (ip->ihl << 2);

    if ( remaining < (int)sizeof(struct tcphdr) ) {
        return;
    }

    if ((destid = match_response(tp, (struct tcphdr *)packet, false)) >= 0) {
        int64_t delay;

        tp->info[destid].icmptype = icmp->type;
        tp->info[destid].icmpcode = icmp->code;
        tp->info[destid].reply = ICMP_REPLY;
        tp->outstanding --;

        delay = DIFF_TV_US(ts, tp->info[destid].time_sent);
        if ( delay > 0 ) {
            tp->info[destid].delay = (uint32_t)delay;
        } else {
            tp->info[destid].delay = 0;
        }
    }
}



/*
 * Process the ICMPv6 header from a response to one of our probes. Check that
 * it is actually one of ours, and then extract timing information etc.
 *
 * Note that I'm avoiding logging "warnings" as we will end up processing
 * every ICMP packet that matches our filter so we don't need to be
 * filling up our logs with warnings about all the other ICMP traffic
 * that our amp monitor is doing.
 */
static void process_icmp6_response(struct tcppingglobals *tp,
        struct icmp6_hdr *icmp, int remaining, struct timeval ts) {

    char *packet = (char *)icmp;
    int destid;

    /*
     * Have to find the original TCP header to try and match this response
     * back to an outgoing SYN
     */
    if ( remaining < (int)sizeof(struct icmp6_hdr) ) {
         return;
    }

    packet += sizeof(struct icmp6_hdr);
    remaining -= sizeof(struct icmp6_hdr);

    if ( remaining < (int)sizeof(struct ip6_hdr) ) {
        return;
    }

    remaining -= sizeof(struct ip6_hdr);
    packet += sizeof(struct ip6_hdr);

    if ( remaining < (int)sizeof(struct tcphdr) ) {
        return;
    }

    if ((destid = match_response(tp, (struct tcphdr *)packet, false)) >= 0) {
        int64_t delay;

        tp->info[destid].icmptype = icmp->icmp6_type;
        tp->info[destid].icmpcode = icmp->icmp6_code;
        tp->info[destid].reply = ICMP_REPLY;
        tp->outstanding --;

        delay = DIFF_TV_US(ts, tp->info[destid].time_sent);
        if ( delay > 0 ) {
            tp->info[destid].delay = (uint32_t)delay;
        } else {
            tp->info[destid].delay = 0;
        }
    }
}



/*
 * Callback used when a packet is received by the pcap filter. This will
 * determine the protocol of the packet and pass it to the appropriate function
 * for processing.
 */
static void receive_packet(wand_event_handler_t *ev_hdl,
        int fd, void *evdata, enum wand_eventtype_t ev) {

    struct pcapdevice *p = (struct pcapdevice *)evdata;
    struct tcppingglobals *tp = (struct tcppingglobals *)p->callbackdata;
    struct pcaptransport transport;

    assert(fd > 0);
    assert(ev == EV_READ);

    transport = pcap_transport_header(p);
    if ( transport.header == NULL || transport.remaining <= 0 ) {
        return;
    }

    if ( transport.protocol == 6 ) {
        Log(LOG_DEBUG, "Received TCP packet on pcap device");
        process_tcp_response(tp, (struct tcphdr *)transport.header,
                transport.remaining, transport.ts);
    }

    if ( transport.protocol == 1 ) {
        process_icmp4_response(tp, (struct icmphdr *)transport.header,
                transport.remaining, transport.ts);
    }

    if ( transport.protocol == 58 ) {
        process_icmp6_response(tp, (struct icmp6_hdr *)transport.header,
                transport.remaining, transport.ts);
    }

    if ( tp->outstanding == 0 && tp->destindex == tp->destcount ) {
        /* All packets have been sent and we are not waiting on any more
         * responses -- exit the event loop so we can report.
         */
        ev_hdl->running = false;
        Log(LOG_DEBUG, "All expected TCPPing responses received");
    }
}



/*
 * Callback used when the timer fires indicating that a packet should be sent.
 * It will determine the next destination to be tested, create an appropriate
 * SYN packet and send it to the destination.
 */
static void send_packet(wand_event_handler_t *ev_hdl, void *evdata) {

    struct tcppingglobals *tp = (struct tcppingglobals *)evdata;
    struct addrinfo *dest = NULL;
    uint16_t srcport;
    int packet_size;
    char *packet = NULL;
    int sock;
    struct sockaddr *srcaddr;
    int delay;

    /* Grab the next available destination */
    assert(tp->destindex < tp->destcount);
    dest = tp->dests[tp->destindex];
    srcaddr = (struct sockaddr *)&(tp->info[tp->destindex].source);

    tp->info[tp->destindex].addr = dest;
    tp->info[tp->destindex].seqno = tp->seqindex + (tp->destindex * 100);
    tp->info[tp->destindex].delay = 0;
    tp->info[tp->destindex].reply = NO_REPLY;
    tp->info[tp->destindex].replyflags = 0;
    tp->info[tp->destindex].icmptype = 0;
    tp->info[tp->destindex].icmpcode = 0;

    if ( !dest->ai_addr ) {
        Log(LOG_INFO, "No address for target %s, skipping", dest->ai_canonname);
        goto nextdest;
    }

    if ( dest->ai_family == AF_INET ) {
        srcport = tp->sourceportv4;
        sock = tp->raw_sockets.socket;
        packet_size = tp->options.packet_size - sizeof(struct iphdr);
    } else if ( dest->ai_family == AF_INET6 ) {
        srcport = tp->sourceportv6;
        sock = tp->raw_sockets.socket6;
        packet_size = tp->options.packet_size - sizeof(struct ip6_hdr);
    } else {
        Log(LOG_WARNING, "Unknown address family: %d", dest->ai_family);
        goto nextdest;
    }

    /* we already know the source address if it has been manually configured */
    if ( dest->ai_family == AF_INET && tp->sourcev4 ) {
        memcpy(srcaddr, tp->sourcev4->ai_addr, sizeof(struct sockaddr_in));
    } else if ( dest->ai_family == AF_INET6 && tp->sourcev6 ) {
        memcpy(srcaddr, tp->sourcev6->ai_addr, sizeof(struct sockaddr_in6));
    } else if ( find_source_address(tp->device, dest, srcaddr) == 0 ) {
        Log(LOG_DEBUG, "Failed to find source address for TCPPing test");
        goto nextdest;
    }

    /* Create a listening pcap fd for the interface */
    if ( pcap_listen(srcaddr, tp->sourceportv4, tp->sourceportv6,
            tp->options.port, tp->device,
            ev_hdl, tp, receive_packet) == -1 ) {
        Log(LOG_WARNING, "Failed to create pcap device for dest %s:%d",
                dest->ai_canonname, tp->options.port);

        goto nextdest;
    }

    packet = calloc(1, packet_size);

    /* Form a TCP SYN packet */
    if ( craft_tcp_syn(tp, packet, srcport, packet_size, srcaddr, dest) < 0 ) {
        Log(LOG_WARNING, "Error while crafting TCP packet for TCPPing test");
        goto nextdest;
    }

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, packet, packet_size, dest,
                    tp->options.inter_packet_delay,
                    &(tp->info[tp->destindex].time_sent))) > 0 ) {
        usleep(delay);
    }

    if ( delay < 0 ) {
        /* zero the timestamp if the packet failed to send properly */
        memset(&(tp->info[tp->destindex].time_sent), 0, sizeof(struct timeval));
    } else {
        tp->outstanding++;
    }

nextdest:
    /* Create a timer for sending the next packet */
    tp->destindex ++;

    if ( tp->destindex == tp->destcount ) {
        Log(LOG_DEBUG, "Reached final target: %d", tp->destindex);
        tp->nextpackettimer = NULL;
        if ( tp->outstanding == 0 ) {
            ev_hdl->running = false;
        } else {
            tp->losstimer = wand_add_timer(ev_hdl, LOSS_TIMEOUT, 0, tp,
                    halt_test);
        }
    } else {
        tp->nextpackettimer = wand_add_timer(ev_hdl,
                (int) (tp->options.inter_packet_delay / 1000000),
                (tp->options.inter_packet_delay % 1000000),
                tp, send_packet);
    }

    if ( packet ) {
        free(packet);
    }
}



/*
 * Construct a protocol buffer message containing the results for a single
 * destination address.
 */
static Amplet2__Tcpping__Item* report_destination(struct info_t *info) {

    Amplet2__Tcpping__Item *item =
        (Amplet2__Tcpping__Item*)malloc(sizeof(Amplet2__Tcpping__Item));

    /* fill the report item with results of a test */
    amplet2__tcpping__item__init(item);
    item->has_family = 1;
    item->family = info->addr->ai_family;
    item->name = address_to_name(info->addr);
    item->has_address = copy_address_to_protobuf(&item->address, info->addr);

    switch ( info->reply ) {
        case NO_REPLY:
            item->has_rtt = 0;
            item->has_icmptype = 0;
            item->has_icmpcode = 0;
            item->flags = NULL;
            break;

        case TCP_REPLY:
            item->flags = (Amplet2__Tcpping__TcpFlags*)malloc(
                    sizeof(Amplet2__Tcpping__TcpFlags));

            item->has_rtt = 1;
            item->rtt = info->delay;

            amplet2__tcpping__tcp_flags__init(item->flags);

            if ( info->replyflags & 0x01 ) {
                item->flags->has_fin = 1;
                item->flags->fin = 1;
            }
            if ( info->replyflags & 0x02 ) {
                item->flags->has_syn = 1;
                item->flags->syn = 1;
            }
            if ( info->replyflags & 0x04 ) {
                item->flags->has_rst = 1;
                item->flags->rst = 1;
            }
            if ( info->replyflags & 0x08 ) {
                item->flags->has_psh = 1;
                item->flags->psh = 1;
            }
            if ( info->replyflags & 0x10 ) {
                item->flags->has_ack = 1;
                item->flags->ack = 1;
            }
            if ( info->replyflags & 0x20 ) {
                item->flags->has_urg = 1;
                item->flags->urg = 1;
            }
            item->has_icmptype = 0;
            item->has_icmpcode = 0;
            break;

        case ICMP_REPLY:
            /*
             * TODO check if the ICMP response is from the target, consider
             * using it to generate an RTT?
             */
            item->has_rtt = 0;
            item->has_icmptype = 1;
            item->icmptype = info->icmptype;
            item->has_icmpcode = 1;
            item->icmpcode = info->icmpcode;
            item->flags = NULL;
            break;
    };

    Log(LOG_DEBUG, "tcpping result: %dus, %d,%d,%d,%d",
            item->rtt ? (int)item->rtt : -1, info->reply, info->replyflags,
            info->icmptype, info->icmpcode);

    return item;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for each destination address.
 */
static amp_test_result_t* report_results(struct timeval *start_time, int count,
        struct info_t info[], struct opt_t *opt) {

    int i;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Amplet2__Tcpping__Report msg = AMPLET2__TCPPING__REPORT__INIT;
    Amplet2__Tcpping__Header header = AMPLET2__TCPPING__HEADER__INIT;
    Amplet2__Tcpping__Item **reports;

    header.has_packet_size = 1;
    header.packet_size = opt->packet_size;
    header.has_random = 1;
    header.random = opt->random;
    header.has_port = 1;
    header.port = opt->port;
    header.has_dscp = 1;
    header.dscp = opt->dscp;

    /* build up the repeated reports section with each of the results */
    reports = malloc(sizeof(Amplet2__Tcpping__Item*) * count);
    for ( i = 0; i < count; i++ ) {
        reports[i] = report_destination(&info[i]);
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = count;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__tcpping__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__tcpping__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < count; i++ ) {
        if ( reports[i]->flags ) {
            free(reports[i]->flags);
        }
        free(reports[i]);
    }

    free(reports);

    return result;
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-tcpping [-hrvx] [-p perturbate] [-s packetsize]\n"
            "                   [-P port] [-Q codepoint] [-Z interpacketgap]\n"
            "                   [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
            "                   -- destination1 [destination2 ... destinationN]"
            "\n\n");

    /* test specific options */
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -P, --port                     "
            "The port number to probe on the target host\n");
    fprintf(stderr, "  -p, --perturbate     <ms>      "
            "Maximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -r, --random                   "
            "Use a random packet size for each test\n");
    fprintf(stderr, "  -s, --size           <bytes>   "
            "Fixed packet size to use for each test\n");

    print_probe_usage();
    print_interface_usage();
    print_generic_usage();
}



/*
 * Main function to run the tcpping test, returning a result structure that
 * will later be printed or sent across the network.
 */
amp_test_result_t* run_tcpping(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    struct timeval start_time;
    struct tcppingglobals *globals;
    wand_event_handler_t *ev_hdl = NULL;
    amp_test_result_t *result;
    char *address_string;

    Log(LOG_DEBUG, "Starting TCPPing test");
    wand_event_init();
    ev_hdl = wand_create_event_handler();

    globals = (struct tcppingglobals *)malloc(sizeof(struct tcppingglobals));

    /* Set defaults before processing options */
    globals->options.inter_packet_delay = MIN_INTER_PACKET_DELAY;
    globals->options.dscp = DEFAULT_DSCP_VALUE;
    globals->options.packet_size = MIN_TCPPING_PROBE_LEN;
    globals->options.random = 0;
    globals->options.perturbate = 0;
    globals->options.port = DEFAULT_TCPPING_PORT;
    globals->sourcev4 = NULL;
    globals->sourcev6 = NULL;
    globals->device = NULL;

    while ( (opt = getopt_long(argc, argv, "P:p:rs:I:Q:Z:4::6::hvx",
                long_options, NULL)) != -1 ) {
        switch (opt) {
            case '4': address_string = parse_optional_argument(argv);
                      /* -4 without address is sorted at a higher level */
                      if ( address_string ) {
                          globals->sourcev4 =
                              get_numeric_address(address_string, NULL);
                      };
                      break;
            case '6': address_string = parse_optional_argument(argv);
                      /* -6 without address is sorted at a higher level */
                      if ( address_string ) {
                          globals->sourcev6 =
                              get_numeric_address(address_string, NULL);
                      };
                      break;
            case 'I': globals->device = strdup(optarg); break;
            case 'Q': if ( parse_dscp_value(optarg,
                                  &globals->options.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': globals->options.inter_packet_delay = atoi(optarg); break;
            case 'P': globals->options.port = atoi(optarg); break;
            case 'p': globals->options.perturbate = atoi(optarg); break;
            case 'r': globals->options.random = 1; break;
            case 's': globals->options.packet_size = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( count < 1 ) {
        Log(LOG_WARNING, "No resolvable destinations were specified!");
        exit(EXIT_FAILURE);
    }

    /* Process and act upon the packet size and perturbation options */
    process_options(globals);

    /* Open and bind the raw sockets required for this test */
    if ( !open_sockets(globals) ) {
        return NULL;
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
        Log(LOG_ERR, "Could not gettimeofday(), aborting test");
        return NULL;
    }

    /* Get the source ports for our sockets */
    if (!listen_source_ports(globals)) {
        return NULL;
    }

    /* Start our sequence numbers from a random value and increment */
    globals->seqindex = rand();
    globals->info = (struct info_t *)malloc(sizeof(struct info_t) * count);
    globals->destindex = 0;
    globals->destcount = count;
    globals->outstanding = 0;
    globals->dests = dests;
    globals->nextpackettimer = NULL;
    globals->losstimer = NULL;

    /* catch a SIGINT and end the test early */
    wand_add_signal(SIGINT, NULL, interrupt_test);

    /*
     * Send a SYN to our first destination at time zero (immediately). This
     * will setup a timer callback for sending the next packet and a fd
     * callback for any response.
     */
    globals->nextpackettimer = wand_add_timer(ev_hdl, 0, 0, globals,
            send_packet);

    wand_event_run(ev_hdl);

    if ( globals->losstimer ) {
        wand_del_timer(ev_hdl, globals->losstimer);
    }

    if ( globals->nextpackettimer ) {
        wand_del_timer(ev_hdl, globals->nextpackettimer);
    }

    pcap_cleanup(ev_hdl);

    close_sockets(globals);

    /* send report */
    result = report_results(&start_time, globals->destcount, globals->info,
            &globals->options);

    free(globals->device);
    free(globals->info);
    free(globals);
    wand_destroy_event_handler(ev_hdl);

    return result;
}



/*
 * Print tcpping test results to stdout, nicely formatted for the standalone
 * test
 */
void print_tcpping(amp_test_result_t *result) {
    Amplet2__Tcpping__Report *msg;
    Amplet2__Tcpping__Item *item;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__tcpping__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print global configuration options */
    printf("\n");
    printf("AMP TCPPing test to port %u, %zu destinations, %u byte packets ",
            msg->header->port, msg->n_reports, msg->header->packet_size);

    if ( msg->header->random ) {
        printf("(random size)\n");
    } else {
        printf("(fixed size)\n");
    }

    printf("    DSCP %s (0x%0x)\n", dscp_to_str(msg->header->dscp),
            msg->header->dscp);

    /* print each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];

        printf("%s", item->name);

        if ( !item->has_address ) {
            /* couldn't resolve the target, didn't test to it */
            snprintf(addrstr, INET6_ADDRSTRLEN, "unresolved %s",
                    family_to_string(item->family));
            printf(" (%s) not tested\n", addrstr);
            continue;
        }

        inet_ntop(item->family, item->address.data, addrstr, INET6_ADDRSTRLEN);
        printf(" (%s)", addrstr);

        if ( item->has_rtt ) {
            /* anything with an rtt is currently TCP only, should have flags */
            printf(" %dus ", item->rtt);

            if ( item->flags->has_syn && item->flags->syn )
                printf("SYN ");
            if ( item->flags->has_fin && item->flags->fin )
                printf("FIN ");
            if ( item->flags->has_urg && item->flags->urg )
                printf("URG ");
            if ( item->flags->has_psh && item->flags->psh )
                printf("PSH ");
            if ( item->flags->has_rst && item->flags->rst )
                printf("RST ");
            if ( item->flags->has_ack && item->flags->ack )
                printf("ACK ");
        } else if ( item->has_icmptype && item->has_icmpcode ) {
            /* print any icmp errors we got, there won't be an rtt */
            printf(" %s (icmp %u/%u)",
                    icmp_code_str(item->family, item->icmptype, item->icmpcode),
                    item->icmptype, item->icmpcode);
        } else {
            /* no response of any sort */
            printf(" missing " );
        }
        printf("\n");
    }
    printf("\n");

    amplet2__tcpping__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* Defined in tests.h */
    new_test->id = AMP_TEST_TCPPING;
    new_test->name = strdup("tcpping");
    new_test->max_targets = 0;
    new_test->min_targets = 1;
    new_test->max_duration = 120;
    new_test->run_callback = run_tcpping;
    new_test->print_callback = print_tcpping;
    new_test->server_callback = NULL;
    new_test->sigint = 1;
    return new_test;
}



#if UNIT_TEST
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt) {
    return report_results(start_time, count, info, opt);
}
#endif

/* vim: set sw=4 tabstop=4 softtabstop=4 expandtab : */
