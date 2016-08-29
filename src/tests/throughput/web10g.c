/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Richard Sanger
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

/**
 * Queries web10g for a given connection returning web10g results
 * for the throughput test.
 *
 * Based upon my own work included in ndt see ndt/src/web10g_util
 *
 * @author Richard Sanger
 */

#include "throughput.h"

#ifdef HAVE_ESTATS
#include <estats/estats.h>

#define Chk(x) \
    do { \
        err = (x); \
        if (err != NULL) { \
            goto Cleanup; \
        } \
    } while (0)

#define ChkIgn(x) \
    do { \
        err = (x); \
        if (err != NULL) { \
            estats_error_free(&err); \
            goto Cleanup; \
        } \
    } while (0)

#define SWAP(x, y) \
    do { \
        typeof(x) tmp; \
        tmp = x; \
        x = y; \
        y = tmp; \
    } while (0)

#define PRINT_AND_FREE(err) \
    do { \
        estats_error_print(stderr, err); \
        estats_error_free(&err); \
    } while (0)


/**
 * Converts a IPv4-mapped IPv6 sockaddr_in6 to a sockaddr_in4
 *
 * @param ss a sockaddr_storage
 *
 * @return if the ss represents a IPv6 mapped IPv4 address it will be converted
 * into a IPv4 sockaddr_in. Otherwise ss will remain unchanged.
 */
static void ipv4mapped_to_ipv4(struct sockaddr_storage * ss){
    if (ss->ss_family == AF_INET6){
        if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *) ss)->sin6_addr)){
        // Ports already in the right place so just move the actual address
        ss->ss_family = AF_INET;
        ((struct sockaddr_in *) ss)->sin_addr.s_addr =
            ((uint32_t *) &((struct sockaddr_in6 *) ss)->sin6_addr)[3];
        }
    }
}

/**
 * Find the web10g connection number related to a given socket.
 *
 * @param client A web10g client
 * @param sockfd The socket file descriptor
 *
 * @return The connection number if successful. If an error occurs -1
 * will be returned.
 *
 */
static struct estats_error * web10g_connection_from_socket(
                    struct estats_nl_client* client, int sockfd, int * connection_id) {
    struct estats_error* err = NULL;
    struct sockaddr_storage local_name;
    struct sockaddr_storage peer_name;
    socklen_t local_name_len = sizeof(local_name);
    socklen_t peer_name_len = sizeof(peer_name);
    *connection_id = -1;

    /* Get the ip address of ourself on the localsocket */
    if (getsockname(sockfd, (struct sockaddr*) &local_name,
                  &local_name_len) == -1) {
        return estats_error_new(ESTATS_ERR_UNKNOWN,
            "getsockname() failed", __FILE__, __LINE__, __FUNCTION__);
    }
    ipv4mapped_to_ipv4(&local_name);

    /* Get the ip address of our peer */
    if (getpeername(sockfd, (struct sockaddr*) &peer_name,
                  &peer_name_len) == -1) {
        return estats_error_new(ESTATS_ERR_UNKNOWN,
            "getpeername() failed", __FILE__, __LINE__, __FUNCTION__);

    }
    ipv4mapped_to_ipv4(&peer_name);

    /* We have our sockaddrs so find the match in the Web10g table */
    struct estats_connection_list* clist = NULL;
    Chk(estats_connection_list_new(&clist));
    Chk(estats_list_conns(clist, client));
    struct estats_list* list_pos;

    ESTATS_LIST_FOREACH(list_pos, &(clist->connection_head)){
        struct estats_connection* cp = ESTATS_LIST_ENTRY(list_pos, estats_connection, list);
		struct estats_connection_tuple* ct = (struct estats_connection_tuple*) cp;

        /* I'm assuming local_name and remote_name should both be on
        * the same addressing scheme i.e. either IPv4 or IPv6 not a mix of both */
        if (local_name.ss_family == AF_INET &&
            peer_name.ss_family == AF_INET &&
            ct->local_addr[16] == ESTATS_ADDRTYPE_IPV4 &&
            ct->rem_addr[16] == ESTATS_ADDRTYPE_IPV4) {
            /* All IPv4 - compare addresses */
            struct sockaddr_in * ipv4_local = (struct sockaddr_in *) &local_name;
            struct sockaddr_in * ipv4_peer = (struct sockaddr_in *) &peer_name;

            /* Compare local and remote ports and addresses */
            if (ct->local_port == ntohs(ipv4_local->sin_port) &&
                ct->rem_port == ntohs(ipv4_peer->sin_port) &&
                ((struct in_addr*) ct->rem_addr)->s_addr == ipv4_peer->sin_addr.s_addr &&
                ((struct in_addr*) ct->local_addr)->s_addr == ipv4_local->sin_addr.s_addr ) {
                /* Found it */
                *connection_id = ct->cid;
                Log(LOG_INFO, "Matched socket to web10g IPv4 connection #%d",
                    *connection_id);
                goto Cleanup;
            }
        } else if (local_name.ss_family == AF_INET6 &&
                   peer_name.ss_family == AF_INET6 &&
                   ct->local_addr[16] == ESTATS_ADDRTYPE_IPV6 &&
                   ct->rem_addr[16] == ESTATS_ADDRTYPE_IPV6) {
            /* We are IPv6  - compare addresses */
            struct sockaddr_in6 * ipv6_local = (struct sockaddr_in6 *) &local_name;
            struct sockaddr_in6 * ipv6_peer = (struct sockaddr_in6 *) &peer_name;

            /* Compare local and remote ports and addresses */
            if (ct->local_port == ntohs(ipv6_local->sin6_port) &&
                ct->rem_port == ntohs(ipv6_peer->sin6_port) &&
                memcmp(ct->rem_addr, ipv6_peer->sin6_addr.s6_addr, sizeof(struct in6_addr)) == 0 &&
                memcmp(ct->local_addr, ipv6_local->sin6_addr.s6_addr, sizeof(struct in6_addr)) == 0) {
                /* Found it */
                *connection_id = ct->cid;
                Log(LOG_INFO, "Matched socket to web10g IPv6 connection #%d",
                    *connection_id);
                goto Cleanup;
            }
        }
    }

    Cleanup:
    estats_connection_list_free(&clist);
    return err;
}



/* Verify type with c - Any good compiler should remove the switch
 * _type_ is a constant value
 * Can do little endian conversion here !!*/
#define ASSIGN_VAR(_name_, _type_) if(strcmp(#_name_, estats_var_array[i].name) == 0) { \
        switch (_type_){ \
            case ESTATS_UNSIGNED64: \
                web10g->_name_ = htobe64(data->val[i].uv64); \
                break;\
            case ESTATS_UNSIGNED32: \
                web10g->_name_ = htobe32(data->val[i].uv32); \
                break;\
            case ESTATS_SIGNED32: \
                web10g->_name_ = htobe32(data->val[i].sv32); \
                break;\
            case ESTATS_UNSIGNED16: \
                web10g->_name_ = htobe16(data->val[i].uv16); \
                break;\
            case ESTATS_UNSIGNED8: \
                web10g->_name_ = data->val[i].uv8; \
                break;\
        } \
    }

/* Fills the web10g structure */
static void fillWeb10G(struct report_web10g_t * web10g, estats_val_data * data){
    int i;
    for(i = 0; i < data->length ; i++){
        if (data->val[i].masked)
            continue;
        /* TODO compare numbers not strings?? */
        ASSIGN_VAR(SegsOut,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DataSegsOut,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DataOctetsOut,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(HCDataOctetsOut,ESTATS_UNSIGNED64)
        else ASSIGN_VAR(SegsRetrans,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(OctetsRetrans,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SegsIn,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DataSegsIn,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DataOctetsIn,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(HCDataOctetsIn,ESTATS_UNSIGNED64)
        else ASSIGN_VAR(ElapsedSecs,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ElapsedMicroSecs,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(StartTimeStamp,ESTATS_UNSIGNED8)
        else ASSIGN_VAR(CurMSS,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(PipeSize,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxPipeSize,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SmoothedRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurRTO,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CongSignals,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurSsthresh,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(Timeouts,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurRwinSent,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxRwinSent,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ZeroRwinSent,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurRwinRcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxRwinRcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ZeroRwinRcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndLimTransRwin,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndLimTransCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndLimTransSnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndLimTimeRwin,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndLimTimeCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndLimTimeSnd,ESTATS_UNSIGNED32)

        else ASSIGN_VAR(RetranThresh,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(NonRecovDAEpisodes,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SumOctetsReordered,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(NonRecovDA,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SampleRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(RTTVar,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MinRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SumRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(HCSumRTT,ESTATS_UNSIGNED64)
        else ASSIGN_VAR(CountRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxRTO,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MinRTO,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(IpTtl,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(IpTosIn,ESTATS_UNSIGNED8)
        else ASSIGN_VAR(IpTosOut,ESTATS_UNSIGNED8)
        else ASSIGN_VAR(PreCongSumCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(PreCongSumRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(PostCongSumRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(PostCongCountRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ECNsignals,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DupAckEpisodes,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(RcvRTT,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DupAcksOut,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CERcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ECESent,ESTATS_UNSIGNED32)

        else ASSIGN_VAR(ActiveOpen,ESTATS_SIGNED32)
        else ASSIGN_VAR(MSSSent,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MSSRcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(WinScaleSent,ESTATS_SIGNED32)
        else ASSIGN_VAR(WinScaleRcvd,ESTATS_SIGNED32)
        else ASSIGN_VAR(TimeStamps,ESTATS_SIGNED32)
        else ASSIGN_VAR(ECN,ESTATS_SIGNED32)
        else ASSIGN_VAR(WillSendSACK,ESTATS_SIGNED32)
        else ASSIGN_VAR(WillUseSACK,ESTATS_SIGNED32)
        else ASSIGN_VAR(State,ESTATS_SIGNED32)
        else ASSIGN_VAR(Nagle,ESTATS_SIGNED32)
        else ASSIGN_VAR(MaxSsCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxCaCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxSsthresh,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MinSsthresh,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(InRecovery,ESTATS_SIGNED32)
        else ASSIGN_VAR(DupAcksIn,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SpuriousFrDetected,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SpuriousRtoDetected,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SoftErrors,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SoftErrorReason,ESTATS_SIGNED32)
        else ASSIGN_VAR(SlowStart,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CongAvoid,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(OtherReductions,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CongOverCount,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(FastRetran,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SubsequentTimeouts,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurTimeoutCount,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(AbruptTimeouts,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SACKsRcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SACKBlocksRcvd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SendStall,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(DSACKDups,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxMSS,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MinMSS,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndInitial,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(RecInitial,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurRetxQueue,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxRetxQueue,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurReasmQueue,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxReasmQueue,ESTATS_UNSIGNED32)

        else ASSIGN_VAR(SndUna,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndNxt,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(SndMax,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ThruOctetsAcked,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(HCThruOctetsAcked,ESTATS_UNSIGNED64)
        else ASSIGN_VAR(RcvNxt,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(ThruOctetsReceived,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(HCThruOctetsReceived,ESTATS_UNSIGNED64)
        else ASSIGN_VAR(CurAppWQueue,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxAppWQueue,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(CurAppRQueue,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(MaxAppRQueue,ESTATS_UNSIGNED32)

        else ASSIGN_VAR(LimCwnd,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(LimSsthresh,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(LimRwin,ESTATS_UNSIGNED32)
        else ASSIGN_VAR(LimMSS,ESTATS_UNSIGNED32)
    }
}


/**
 * Given the TCP socket queries web10g and attempts to return the web10g
 * estats for that connection
 *
 * @param socket
 *          The socket to get the Web10G stats from
 * @return A malloc'd report_web10g_t structure. Or NULL upon failure.
 *         **report_web10g_t will be in Big Endian byte order**
 */
struct report_web10g_t * getWeb10GSnap(int socket){
    estats_error* err = NULL;
    estats_val_data * data = NULL;
    struct estats_nl_client *client = NULL;
    int cid = 0;
    struct report_web10g_t * web10g = NULL;

    if(client == NULL)
        Chk(estats_nl_client_init(&client));

    Chk(estats_val_data_new(&data));
    Chk(web10g_connection_from_socket(client, socket, &cid));
    Chk(estats_read_vars(data, cid, client));

    web10g = malloc(sizeof(struct report_web10g_t));
    memset(web10g, 0, sizeof(struct report_web10g_t));

    fillWeb10G(web10g, data);

    Cleanup:
    estats_val_data_free(&data);
    estats_nl_client_destroy(&client);

    if (err != NULL) {
		PRINT_AND_FREE(err);
	}
    return web10g;
}

#endif

/* Verify type with c - Any good compiler should remove the switch
 * _type_ is a constant value */
#define PRINT_VAR(_name_, _type_, _bo_) \
    printf("------Found web10g var %s : %" _type_ " (" _type_ ")\n", \
            #_name_, _bo_(web10g->_name_));

/**
 * Prints all the enclosed web10g values out
 *
 * @param web10g
 *          A report_web10g_t structure retrevied from getWeb10GSnap()
 *          this is expected to be in Big Endian byte order.
 */
void print_web10g(struct report_web10g_t * web10g){
    PRINT_VAR(SegsOut,PRIu32,be32toh)
    PRINT_VAR(DataSegsOut,PRIu32,be32toh)
    PRINT_VAR(DataOctetsOut,PRIu32,be32toh)
    PRINT_VAR(HCDataOctetsOut,PRIu64,be64toh)
    PRINT_VAR(SegsRetrans,PRIu32,be32toh)
    PRINT_VAR(OctetsRetrans,PRIu32,be32toh)
    PRINT_VAR(SegsIn,PRIu32,be32toh)
    PRINT_VAR(DataSegsIn,PRIu32,be32toh)
    PRINT_VAR(DataOctetsIn,PRIu32,be32toh)
    PRINT_VAR(HCDataOctetsIn,PRIu64,be64toh)
    PRINT_VAR(ElapsedSecs,PRIu32,be32toh)
    PRINT_VAR(ElapsedMicroSecs,PRIu32,be32toh)
    PRINT_VAR(StartTimeStamp,PRIu8,)
    PRINT_VAR(CurMSS,PRIu32,be32toh)
    PRINT_VAR(PipeSize,PRIu32,be32toh)
    PRINT_VAR(MaxPipeSize,PRIu32,be32toh)
    PRINT_VAR(SmoothedRTT,PRIu32,be32toh)
    PRINT_VAR(CurRTO,PRIu32,be32toh)
    PRINT_VAR(CongSignals,PRIu32,be32toh)
    PRINT_VAR(CurCwnd,PRIu32,be32toh)
    PRINT_VAR(CurSsthresh,PRIu32,be32toh)
    PRINT_VAR(Timeouts,PRIu32,be32toh)
    PRINT_VAR(CurRwinSent,PRIu32,be32toh)
    PRINT_VAR(MaxRwinSent,PRIu32,be32toh)
    PRINT_VAR(ZeroRwinSent,PRIu32,be32toh)
    PRINT_VAR(CurRwinRcvd,PRIu32,be32toh)
    PRINT_VAR(MaxRwinRcvd,PRIu32,be32toh)
    PRINT_VAR(ZeroRwinRcvd,PRIu32,be32toh)
    PRINT_VAR(SndLimTransRwin,PRIu32,be32toh)
    PRINT_VAR(SndLimTransCwnd,PRIu32,be32toh)
    PRINT_VAR(SndLimTransSnd,PRIu32,be32toh)
    PRINT_VAR(SndLimTimeRwin,PRIu32,be32toh)
    PRINT_VAR(SndLimTimeCwnd,PRIu32,be32toh)
    PRINT_VAR(SndLimTimeSnd,PRIu32,be32toh)

    PRINT_VAR(RetranThresh,PRIu32,be32toh)
    PRINT_VAR(NonRecovDAEpisodes,PRIu32,be32toh)
    PRINT_VAR(SumOctetsReordered,PRIu32,be32toh)
    PRINT_VAR(NonRecovDA,PRIu32,be32toh)
    PRINT_VAR(SampleRTT,PRIu32,be32toh)
    PRINT_VAR(RTTVar,PRIu32,be32toh)
    PRINT_VAR(MaxRTT,PRIu32,be32toh)
    PRINT_VAR(MinRTT,PRIu32,be32toh)
    PRINT_VAR(SumRTT,PRIu32,be32toh)
    PRINT_VAR(HCSumRTT,PRIu64,be64toh)
    PRINT_VAR(CountRTT,PRIu32,be32toh)
    PRINT_VAR(MaxRTO,PRIu32,be32toh)
    PRINT_VAR(MinRTO,PRIu32,be32toh)
    PRINT_VAR(IpTtl,PRIu32,be32toh)
    PRINT_VAR(IpTosIn,PRIu8,)
    PRINT_VAR(IpTosOut,PRIu8,)
    PRINT_VAR(PreCongSumCwnd,PRIu32,be32toh)
    PRINT_VAR(PreCongSumRTT,PRIu32,be32toh)
    PRINT_VAR(PostCongSumRTT,PRIu32,be32toh)
    PRINT_VAR(PostCongCountRTT,PRIu32,be32toh)
    PRINT_VAR(ECNsignals,PRIu32,be32toh)
    PRINT_VAR(DupAckEpisodes,PRIu32,be32toh)
    PRINT_VAR(RcvRTT,PRIu32,be32toh)
    PRINT_VAR(DupAcksOut,PRIu32,be32toh)
    PRINT_VAR(CERcvd,PRIu32,be32toh)
    PRINT_VAR(ECESent,PRIu32,be32toh)

    PRINT_VAR(ActiveOpen,PRId32,be32toh)
    PRINT_VAR(MSSSent,PRIu32,be32toh)
    PRINT_VAR(MSSRcvd,PRIu32,be32toh)
    PRINT_VAR(WinScaleSent,PRId32,be32toh)
    PRINT_VAR(WinScaleRcvd,PRId32,be32toh)
    PRINT_VAR(TimeStamps,PRId32,be32toh)
    PRINT_VAR(ECN,PRId32,be32toh)
    PRINT_VAR(WillSendSACK,PRId32,be32toh)
    PRINT_VAR(WillUseSACK,PRId32,be32toh)
    PRINT_VAR(State,PRId32,be32toh)
    PRINT_VAR(Nagle,PRId32,be32toh)
    PRINT_VAR(MaxSsCwnd,PRIu32,be32toh)
    PRINT_VAR(MaxCaCwnd,PRIu32,be32toh)
    PRINT_VAR(MaxSsthresh,PRIu32,be32toh)
    PRINT_VAR(MinSsthresh,PRIu32,be32toh)
    PRINT_VAR(InRecovery,PRId32,be32toh)
    PRINT_VAR(DupAcksIn,PRIu32,be32toh)
    PRINT_VAR(SpuriousFrDetected,PRIu32,be32toh)
    PRINT_VAR(SpuriousRtoDetected,PRIu32,be32toh)
    PRINT_VAR(SoftErrors,PRIu32,be32toh)
    PRINT_VAR(SoftErrorReason,PRId32,be32toh)
    PRINT_VAR(SlowStart,PRIu32,be32toh)
    PRINT_VAR(CongAvoid,PRIu32,be32toh)
    PRINT_VAR(OtherReductions,PRIu32,be32toh)
    PRINT_VAR(CongOverCount,PRIu32,be32toh)
    PRINT_VAR(FastRetran,PRIu32,be32toh)
    PRINT_VAR(SubsequentTimeouts,PRIu32,be32toh)
    PRINT_VAR(CurTimeoutCount,PRIu32,be32toh)
    PRINT_VAR(AbruptTimeouts,PRIu32,be32toh)
    PRINT_VAR(SACKsRcvd,PRIu32,be32toh)
    PRINT_VAR(SACKBlocksRcvd,PRIu32,be32toh)
    PRINT_VAR(SendStall,PRIu32,be32toh)
    PRINT_VAR(DSACKDups,PRIu32,be32toh)
    PRINT_VAR(MaxMSS,PRIu32,be32toh)
    PRINT_VAR(MinMSS,PRIu32,be32toh)
    PRINT_VAR(SndInitial,PRIu32,be32toh)
    PRINT_VAR(RecInitial,PRIu32,be32toh)
    PRINT_VAR(CurRetxQueue,PRIu32,be32toh)
    PRINT_VAR(MaxRetxQueue,PRIu32,be32toh)
    PRINT_VAR(CurReasmQueue,PRIu32,be32toh)
    PRINT_VAR(MaxReasmQueue,PRIu32,be32toh)

    PRINT_VAR(SndUna,PRIu32,be32toh)
    PRINT_VAR(SndNxt,PRIu32,be32toh)
    PRINT_VAR(SndMax,PRIu32,be32toh)
    PRINT_VAR(ThruOctetsAcked,PRIu32,be32toh)
    PRINT_VAR(HCThruOctetsAcked,PRIu64,be64toh)
    PRINT_VAR(RcvNxt,PRIu32,be32toh)
    PRINT_VAR(ThruOctetsReceived,PRIu32,be32toh)
    PRINT_VAR(HCThruOctetsReceived,PRIu64,be64toh)
    PRINT_VAR(CurAppWQueue,PRIu32,be32toh)
    PRINT_VAR(MaxAppWQueue,PRIu32,be32toh)
    PRINT_VAR(CurAppRQueue,PRIu32,be32toh)
    PRINT_VAR(MaxAppRQueue,PRIu32,be32toh)

    PRINT_VAR(LimCwnd,PRIu32,be32toh)
    PRINT_VAR(LimSsthresh,PRIu32,be32toh)
    PRINT_VAR(LimRwin,PRIu32,be32toh)
    PRINT_VAR(LimMSS,PRIu32,be32toh)

};
