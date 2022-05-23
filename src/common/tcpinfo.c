/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2022 The University of Waikato, Hamilton, New Zealand.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "config.h"
#include "debug.h"
#include "tcpinfo.h"


/*
 * Query the socket for some more in-depth information about the TCP state.
 */
struct tcpinfo_result *get_tcp_info(int sock_fd) {
    struct tcpinfo_result *result;
    struct amp_tcp_info *tcp_info = calloc(1, sizeof(struct amp_tcp_info));
    int tcp_info_len = sizeof(struct amp_tcp_info);
    int attempts = 10;

    Log(LOG_DEBUG, "Getting tcp info struct for socket");

    do {
        /* get the tcp info block */
        if ( getsockopt(sock_fd, IPPROTO_TCP, TCP_INFO, (void *)tcp_info,
                    (socklen_t *)&tcp_info_len) < 0 ) {
            perror("getsockopt");
            free(tcp_info);
            return NULL;
        }
        /* delay until all bytes have been sent or we've waited long enough */
        attempts--;
    } while ( attempts > 0 && tcp_info->tcpi_notsent_bytes > 0 &&
            usleep(100000) == 0 );

    /*
     * don't try to parse any results that don't match our expected format -
     * new fields get added at any point in the structure so we can't be sure
     * that we are getting the correct data.
     */
    if ( tcp_info_len != sizeof(struct amp_tcp_info) ) {
        free(tcp_info);
        return NULL;
    }

    result = calloc(1, sizeof(struct tcpinfo_result));

    /*
     * if the connection isn't app limited then the delivery rate is the most
     * recent value rather than the maximum
     * TODO why isn't it always app limited when we have no data left to send?
     * https://github.com/torvalds/linux/commit/eb8329e0a04db0061f714f033b4454
     * https://github.com/torvalds/linux/commit/b9f64820fb226a4e8ab10591f46cec
     * https://github.com/torvalds/linux/commit/d7722e8570fc0f1e003cee7cf37694
     */
    if ( tcp_info->tcpi_delivery_rate_app_limited ) {
        result->delivery_rate = tcp_info->tcpi_delivery_rate;
    }

    result->total_retrans = tcp_info->tcpi_total_retrans;
    result->rtt = tcp_info->tcpi_rtt;
    result->rttvar = tcp_info->tcpi_rttvar;
    result->min_rtt = tcp_info->tcpi_min_rtt;
    result->busy_time = tcp_info->tcpi_busy_time;
    result->rwnd_limited = tcp_info->tcpi_rwnd_limited;
    result->sndbuf_limited = tcp_info->tcpi_sndbuf_limited;

    free(tcp_info);

    return result;
}
