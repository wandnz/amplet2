/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Authors: Brendon Jones
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
#ifndef _COMMON_TCPINFO_H
#define _COMMON_TCPINFO_H

#include <stdint.h>
#include <linux/types.h>

/*
 * Structure used for report messages involving tcpinfo, with just the
 * particular information we are interested in.
 */
struct tcpinfo_result {
    uint64_t delivery_rate;
    uint64_t busy_time;
    uint64_t rwnd_limited;
    uint64_t sndbuf_limited;
    uint32_t total_retrans;
    uint32_t rtt;
    uint32_t rttvar;
    uint32_t min_rtt;
};

/*
 * Based on linux/include/uapi/linux/tcp.h.
 *
 * This struct appears in this form in the linux kernel from about 4.10, but
 * doesn't appear to be updated in my userspace tools so needs to be included
 * here if we want to use it.
 */
struct amp_tcp_info {
        __u8    tcpi_state;
        __u8    tcpi_ca_state;
        __u8    tcpi_retransmits;
        __u8    tcpi_probes;
        __u8    tcpi_backoff;
        __u8    tcpi_options;
        __u8    tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
        __u8    tcpi_delivery_rate_app_limited:1;

        __u32   tcpi_rto;
        __u32   tcpi_ato;
        __u32   tcpi_snd_mss;
        __u32   tcpi_rcv_mss;

        __u32   tcpi_unacked;
        __u32   tcpi_sacked;
        __u32   tcpi_lost;
        __u32   tcpi_retrans;
        __u32   tcpi_fackets;

        /* Times. */
        __u32   tcpi_last_data_sent;
        __u32   tcpi_last_ack_sent;     /* Not remembered, sorry. */
        __u32   tcpi_last_data_recv;
        __u32   tcpi_last_ack_recv;

        /* Metrics. */
        __u32   tcpi_pmtu;
        __u32   tcpi_rcv_ssthresh;
        __u32   tcpi_rtt;
        __u32   tcpi_rttvar;
        __u32   tcpi_snd_ssthresh;
        __u32   tcpi_snd_cwnd;
        __u32   tcpi_advmss;
        __u32   tcpi_reordering;

        __u32   tcpi_rcv_rtt;
        __u32   tcpi_rcv_space;

        __u32   tcpi_total_retrans;

        __u64   tcpi_pacing_rate;
        __u64   tcpi_max_pacing_rate;
        __u64   tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
        __u64   tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
        __u32   tcpi_segs_out;       /* RFC4898 tcpEStatsPerfSegsOut */
        __u32   tcpi_segs_in;        /* RFC4898 tcpEStatsPerfSegsIn */

	__u32   tcpi_notsent_bytes;
        __u32   tcpi_min_rtt;
        __u32   tcpi_data_segs_in;      /* RFC4898 tcpEStatsDataSegsIn */
        __u32   tcpi_data_segs_out;     /* RFC4898 tcpEStatsDataSegsOut */

        __u64   tcpi_delivery_rate;

        __u64   tcpi_busy_time;      /* Time (usec) busy sending data */
        __u64   tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
        __u64   tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */
};

struct tcpinfo_result *get_tcp_info(int sock_fd);

#endif
