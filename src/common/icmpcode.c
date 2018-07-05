/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
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

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>

#include "icmpcode.h"


/*
 * Convert an ICMPv4 error type and code into a human readable error string.
 */
static char *icmp4_code_str(uint8_t type, uint8_t code) {

    switch ( type ) {
        case ICMP_ECHOREPLY: return "Echo Reply";

        case ICMP_DEST_UNREACH:
            switch ( code ) {
                case ICMP_NET_UNREACH:
                    return "Net Unreachable";
                case ICMP_HOST_UNREACH:
                    return "Host Unreachable";
                case ICMP_PROT_UNREACH:
                    return "Protocol Unreachable";
                case ICMP_PORT_UNREACH:
                    return "Port Unreachable";
                case ICMP_FRAG_NEEDED:
                    return "Fragmentation Needed and Don't Fragment was Set";
                case ICMP_SR_FAILED:
                    return "Source Route Failed";
                case ICMP_NET_UNKNOWN:
                    return "Destination Network Unknown";
                case ICMP_HOST_UNKNOWN:
                    return "Destination Host Unknown";
                case ICMP_HOST_ISOLATED:
                    return "Source Host Isolated";
                case ICMP_NET_ANO:
                    return "Destination Network is Administratively Prohibited";
                case ICMP_HOST_ANO:
                    return "Destination Host is Administratively Prohibited";
                case ICMP_NET_UNR_TOS:
                    return "Destination Network Unreachable for Type of Service";
                case ICMP_HOST_UNR_TOS:
                    return "Destination Host Unreachable for Type of Service";
                case ICMP_PKT_FILTERED:
                    return "Communication Administratively Prohibited";
                case ICMP_PREC_VIOLATION:
                    return "Host Precedence Violation";
                case ICMP_PREC_CUTOFF:
                    return "Precedence Cutoff in effect";
                default:
                    return "Destination Unreachable, Unknown Code";
            };

        case ICMP_SOURCE_QUENCH: return "Source Quench";

        case ICMP_REDIRECT:
            switch ( code ) {
                case ICMP_REDIR_NET:
                    return "Redirect Datagram for the Network";
                case ICMP_REDIR_HOST:
                    return "Redirect Datagram for the Host";
                case ICMP_REDIR_NETTOS:
                    return "Redirect Datagram for the Type of Service and Network";
                case ICMP_REDIR_HOSTTOS:
                    return "Redirect Datagram for the Type of Service and Host";
                default:
                    return "Redirect, Unknown Code";
            };

        case ICMP_ECHO: return "Echo Request";

        case ICMP_TIME_EXCEEDED:
            switch ( code ) {
                case ICMP_EXC_TTL:
                    return "Time to Live Exceeded in Transit";
                case ICMP_EXC_FRAGTIME:
                    return "Fragment Reassembly Time Exceeded";
                default:
                    return "Time Exceeded, Unknown Code";
            };

        case ICMP_PARAMETERPROB: return "Parameter Problem";

        case ICMP_TIMESTAMP: return "Timestamp";

        case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";

        default: return "Unknown Type";
    };
}



/*
 * Convert an ICMPv6 error type and code into a human readable error string.
 */
static char *icmp6_code_str(uint8_t type, uint8_t code) {

    switch ( type ) {
        case ICMP6_DST_UNREACH:
            switch ( code ) {
                case ICMP6_DST_UNREACH_NOROUTE:
                    return "No Route to Destination";
                case ICMP6_DST_UNREACH_ADMIN:
                    return "Communication Administratively Prohibited";
                case ICMP6_DST_UNREACH_BEYONDSCOPE:
                    return "Beyond Scope of Source Address";
                case ICMP6_DST_UNREACH_ADDR:
                    return "Address Unreachable";
                case ICMP6_DST_UNREACH_NOPORT:
                    return "Port Unreachable";
                /*
                case ICMPV6_POLICY_FAIL:
                    return "Source Address Failed Ingress/Egress Policy";
                case ICMPV6_REJECT_ROUTE:
                    return "Reject Route to Destination";
                */
                default:
                    return "Destination Unreachable, Unknown Code";
            };

        case ICMP6_PACKET_TOO_BIG: return "Packet Too Big";

        case ICMP6_TIME_EXCEEDED:
            switch ( code ) {
                case ICMP6_TIME_EXCEED_TRANSIT:
                    return "Hop Limit Exceeded in Transit";
                case ICMP6_TIME_EXCEED_REASSEMBLY:
                    return "Fragment Reassembly Time Exceeded";
                default:
                    return "Time Exceeded, Unknown Code";
            };

        case ICMP6_PARAM_PROB:
            switch ( code ) {
                case ICMP6_PARAMPROB_HEADER:
                    return "Erroneous Header Field Encountered";
                case ICMP6_PARAMPROB_NEXTHEADER:
                    return "Unrecognised Next Header Type Encountered";
                case ICMP6_PARAMPROB_OPTION:
                    return "Unrecognised IPv6 Option Encountered";
                default:
                    return "Parameter Problem, Unknown Code";
            };

        case ICMP6_ECHO_REQUEST: return "Echo Request";

        case ICMP6_ECHO_REPLY: return "Echo Reply";

        case MLD_LISTENER_QUERY: return "Multicase Listener Query";

        case MLD_LISTENER_REPORT: return "Multicast Listener Report";

        case MLD_LISTENER_REDUCTION: return "Multicast Listener Drone";

        case ND_ROUTER_SOLICIT: return "Router Solicitation";

        case ND_ROUTER_ADVERT: return "Router Advertisement";

        case ND_NEIGHBOR_SOLICIT: return "Neighbour Solicitation";

        case ND_NEIGHBOR_ADVERT: return "Neighbour Advertisement";

        case ND_REDIRECT: return "Redirect Message";

        default: return "Unknown Type";
    };
}



/*
 * Convert an ICMP error type and code into a human readable error string.
 */
char *icmp_code_str(uint8_t family, uint8_t type, uint8_t code) {

    switch ( family ) {
        case AF_INET: return icmp4_code_str(type, code);
        case AF_INET6: return icmp6_code_str(type, code);
        default: return "unknown address family";
    };
}
