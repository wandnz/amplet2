#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <string.h>
#include <math.h>

#include "serverlib.h"
#include "udpstream.h"
#include "debug.h"
#include "mos.h"



/*
 * Build a HELLO protocol buffer message containing test options.
 */
ProtobufCBinaryData* build_hello(struct opt_t *options) {
    ProtobufCBinaryData *data = malloc(sizeof(ProtobufCBinaryData));
    Amplet2__Udpstream__Hello hello = AMPLET2__UDPSTREAM__HELLO__INIT;

    hello.has_test_port = 1;
    hello.test_port = options->tport;
    hello.has_packet_size = 1;
    hello.packet_size = options->packet_size;
    hello.has_packet_count = 1;
    hello.packet_count = options->packet_count;
    hello.has_packet_spacing = 1;
    hello.packet_spacing = options->packet_spacing;
    hello.has_percentile_count = 1;
    hello.percentile_count = options->percentile_count;
    hello.has_dscp = 1;
    hello.dscp = options->dscp;
    hello.has_rtt_samples = 1;
    hello.rtt_samples = options->rtt_samples;

    data->len = amplet2__udpstream__hello__get_packed_size(&hello);
    data->data = malloc(data->len);
    amplet2__udpstream__hello__pack(&hello, data->data);

    return data;
}



/*
 * Parse a HELLO protocol buffer message containing test options and return
 * them.
 */
void* parse_hello(ProtobufCBinaryData *data) {
    struct opt_t *options;
    Amplet2__Udpstream__Hello *hello;

    hello = amplet2__udpstream__hello__unpack(NULL, data->len, data->data);
    options = calloc(1, sizeof(struct opt_t));

    options->tport = hello->test_port;
    options->packet_size = hello->packet_size;
    options->packet_count = hello->packet_count;
    options->packet_spacing = hello->packet_spacing;
    options->percentile_count = hello->percentile_count;
    options->dscp = hello->dscp;
    options->rtt_samples = hello->rtt_samples;

    amplet2__udpstream__hello__free_unpacked(hello, NULL);

    return options;
}



/*
 * Build a SEND protocol buffer message containing information on how long
 * to send test data.
 */
ProtobufCBinaryData* build_send(struct opt_t *options) {
    ProtobufCBinaryData *data = malloc(sizeof(ProtobufCBinaryData));
    Amplet2__Udpstream__Send send = AMPLET2__UDPSTREAM__SEND__INIT;

    send.has_test_port = 1;
    send.test_port = options->tport;

    data->len = amplet2__udpstream__send__get_packed_size(&send);
    data->data = malloc(data->len);
    amplet2__udpstream__send__pack(&send, data->data);

    return data;
}



/*
 * Parse a SEND protocol buffer message containing information on how long
 * to send test data and return it.
 */
void* parse_send(ProtobufCBinaryData *data) {
    struct opt_t *options;
    Amplet2__Udpstream__Send *send;

    send = amplet2__udpstream__send__unpack(NULL, data->len, data->data);
    options = calloc(1, sizeof(struct opt_t));

    options->tport = send->test_port;

    amplet2__udpstream__send__free_unpacked(send, NULL);

    return options;
}



/*
 * Send a stream of UDP packets towards the remote target, with the given
 * test options (size, spacing and count).
 */
struct summary_t* send_udp_stream(int sock, struct addrinfo *remote,
        struct opt_t *options) {
    struct timeval now;
    struct payload_t *payload;
    size_t payload_len;
    char response[MAXIMUM_UDPSTREAM_PACKET_LENGTH];
    ssize_t bytes;
    uint32_t i;
    struct socket_t sockets;
    struct summary_t *rtt = NULL;
    double mean = 0;

    Log(LOG_DEBUG, "Sending UDP stream, packets:%d size:%d spacing:%d",
            options->packet_count, options->packet_size,
            options->packet_spacing);

    /* wrap the socket in a socket_t so we can call other amp functions */
    memset(&sockets, 0, sizeof(sockets));
    switch ( remote->ai_family ) {
        case AF_INET:
            sockets.socket = sock;
            payload_len = options->packet_size - sizeof(struct iphdr);
            break;
        case AF_INET6:
            sockets.socket6 = sock;
            payload_len = options->packet_size - sizeof(struct ip6_hdr);
            break;
        default:
            Log(LOG_ERR,"Unknown address family %d",remote->ai_family);
            return NULL;
    };

    if ( options->dscp ) {
        if ( set_dscp_socket_options(&sockets, options->dscp) < 0 ) {
            Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
            return NULL;
        }
    }

    if ( options->rtt_samples > 0 ) {
        rtt = calloc(1, sizeof(struct summary_t));
        rtt->minimum = UINT32_MAX;
    }

    //XXX put a pattern in the payload?
    /* the packet size option includes headers, so subtract them */
    payload_len -= sizeof(struct udphdr);
    payload = (struct payload_t *)calloc(1, payload_len);

    for ( i = 0; i < options->packet_count; i++ ) {
        gettimeofday(&now, NULL);
        payload->index = htonl(i);
        /* this should cast appropriately whether 32 or 64 bit*/
        payload->sec = htobe64(now.tv_sec);
        payload->usec = htobe64(now.tv_usec);

        if ( sendto(sock, payload, payload_len, 0,
                    remote->ai_addr, remote->ai_addrlen) < 0 ) {
            Log(LOG_WARNING, "Error sending udpstream packet: %s",
                    strerror(errno));
            if ( rtt ) {
                free(rtt);
            }
            return NULL;
        }

        if ( options->rtt_samples > 0 ) {
            /*
             * After sending the packet, check for any reflected packets
             * before sending the next one.
             */
            int wait = options->packet_spacing;

            /* TODO timing won't be super accurate, but good enough for now */
            while ( (bytes = get_packet(&sockets, response,
                            MAXIMUM_UDPSTREAM_PACKET_LENGTH,
                            NULL, &wait, &now)) > 0 ) {
                struct payload_t *recv_payload;
                struct timeval sent_time;
                uint32_t value;
                double delta;

                //XXX check that this is actually a related packet

                recv_payload = (struct payload_t*)&response;
                /* this should cast appropriately whether 32 or 64 bit */
                sent_time.tv_sec = (time_t)be64toh(recv_payload->sec);
                sent_time.tv_usec = (time_t)be64toh(recv_payload->usec);
                value = DIFF_TV_US(now, sent_time);
                if ( value > rtt->maximum ) {
                    rtt->maximum = value;
                }
                if ( value < rtt->minimum ) {
                    rtt->minimum = value;
                }
                rtt->samples++;
                delta = (double)value - mean;
                mean += delta / rtt->samples;
            }
        } else {
            usleep(options->packet_spacing);
        }
    }

    if ( options->rtt_samples > 0 ) {
        rtt->mean = (uint32_t)round(mean);
    }

    free(payload);

    return rtt;
}



/*
 * Receive a stream of UDP packets, expecting the specified number of packets.
 */
int receive_udp_stream(int sock, struct opt_t *options, struct timeval *times) {
    char buffer[MAXIMUM_UDPSTREAM_PACKET_LENGTH];
    int timeout;
    uint32_t i;
    struct timeval sent_time, recv_time;
    struct socket_t sockets;
    struct payload_t *payload;
    struct sockaddr_storage ss;
    socklen_t socklen;
    ssize_t bytes;
    uint32_t index;

    socklen = sizeof(ss);
    getsockname(sock, (struct sockaddr *)&ss, &socklen);

    sockets.socket = sock;
    sockets.socket6 = -1;

    Log(LOG_DEBUG, "Receiving UDP stream, packets:%d", options->packet_count);

    for ( i = 0; i < options->packet_count; i++ ) {
        /* reset timeout per packet, consider some global timer also? */
        timeout = UDPSTREAM_LOSS_TIMEOUT;

        if ( (bytes = get_packet(&sockets, buffer, sizeof(buffer),
                        (struct sockaddr*)&ss, &timeout, &recv_time)) > 0 ) {

            payload = (struct payload_t*)&buffer;

            /* get the packet index number so we record it correctly */
            index = ntohl(payload->index);

            /* TODO better checks that the packet belongs to our stream? */
            if ( index < options->packet_count ) {
                /* check if we need to reflect this packet */
                if ( options->rtt_samples > 0 &&
                        index % options->rtt_samples == 0 ) {
                    /* reflect the packet back for rtt measurements */
                    if ( sendto(sock, buffer, bytes, 0,
                                (struct sockaddr*)&ss, socklen) < 0 ) {
                        Log(LOG_DEBUG, "Error reflecting udpstream packet: %s",
                                strerror(errno));
                    }
                }

                /* this should cast appropriately whether 32 or 64 bit */
                sent_time.tv_sec = (time_t)be64toh(payload->sec);
                sent_time.tv_usec = (time_t)be64toh(payload->usec);
                timersub(&recv_time, &sent_time, &times[index]);
                Log(LOG_DEBUG, "Got UDP stream packet %d (id:%d)", i, index);
            }
        } else {
            Log(LOG_DEBUG, "UDP stream packet didn't arrive in time");
        }
    }

    return 0;
}



/*
 * Compare two unsigned 32bit integers, used to quicksort the ipdv array.
 */
static int cmp(const void *a, const void *b) {
    return ( *(uint32_t*)a - *(uint32_t*)b );
}



/*
 * Create a new loss period to count the number of consecutive packets received
 * or dropped.
 */
static Amplet2__Udpstream__Period *new_loss_period(
        Amplet2__Udpstream__Period__Status status) {

    Amplet2__Udpstream__Period *period =
        malloc(sizeof(Amplet2__Udpstream__Period));

    amplet2__udpstream__period__init(period);
    period->has_status = 1;
    period->status = status;
    period->has_length = 1;
    period->length = 1;

    return period;
}



/*
 * Construct a protocol buffer message containing the voip statistics for
 * a single test flow.
 */
Amplet2__Udpstream__Voip* report_voip(Amplet2__Udpstream__Item *item) {
    Amplet2__Udpstream__Voip *voip;
    uint32_t owd;
    int lost = 0, runs = 0;
    unsigned int i;

    if ( !item || !item->rtt ) {
        return NULL;
    }

    voip = calloc(1, sizeof(Amplet2__Udpstream__Voip));
    amplet2__udpstream__voip__init(voip);

    /* assume one-way delay is half the round trip time */
    owd = item->rtt->mean / 2;

    /* calculate the average length of loss runs */
    for ( i = 0; i < item->n_loss_periods; i++ ) {
        if ( item->loss_periods[i]->status ==
                AMPLET2__UDPSTREAM__PERIOD__STATUS__LOST ) {
            lost += item->loss_periods[i]->length;
            runs++;
        }
    }

    /* cisco icpif is pretty basic, similar to cisco sla voip jitter test */
    voip->has_icpif = 1;
    voip->icpif = calculate_icpif(owd + item->jitter->maximum,
            item->loss_percent);

    /* cisco mos is calculated from the icpif score */
    voip->has_cisco_mos = 1;
    voip->cisco_mos = calculate_cisco_mos(voip->icpif);

    /* itu r rating from g.107 e-model */
    voip->has_itu_rating = 1;
    voip->itu_rating = calculate_itu_rating(owd + item->jitter->maximum,
            item->loss_percent, runs ? (lost / runs) : 0);

    /* convert r rating to mos */
    voip->has_itu_mos = 1;
    voip->itu_mos = calculate_itu_mos(voip->itu_rating);

    return voip;
}



/*
 * Construct a protocol buffer message containing the summary statistics for
 * the RTT measurements in a single test flow.
 */
Amplet2__Udpstream__SummaryStats* report_summary(struct summary_t *summary) {
    Amplet2__Udpstream__SummaryStats *stats;

    if ( !summary ) {
        return NULL;
    }

    Log(LOG_DEBUG, "RTT information available");

    stats = calloc(1, sizeof(Amplet2__Udpstream__SummaryStats));
    amplet2__udpstream__summary_stats__init(stats);

    stats->has_maximum = 1;
    stats->maximum = summary->maximum;
    stats->has_minimum = 1;
    stats->minimum = summary->minimum;
    stats->has_mean = 1;
    stats->mean = summary->mean;
    stats->has_samples = 1;
    stats->samples = summary->samples;

    return stats;
}



/*
 * Construct a protocol buffer message containing all the statistics for
 * a single test flow, including packet interarrivals, RTT measurements,
 * VoIP statistics, loss periods etc.
 */
Amplet2__Udpstream__Item* report_stream(enum udpstream_direction direction,
        struct summary_t *rtt, struct timeval *times, struct opt_t *options) {

    Amplet2__Udpstream__Item *item =
        (Amplet2__Udpstream__Item*)malloc(sizeof(Amplet2__Udpstream__Item));
    uint32_t i;
    uint32_t received = 0;
    int32_t current = 0, prev = 0;
    int32_t ipdv[options->packet_count];
    int loss_runs = 0;
    Amplet2__Udpstream__Period *period = NULL;
    struct summary_t jitter;
    double mean = 0, delta;

    Log(LOG_DEBUG, "Reporting udpstream results");

    amplet2__udpstream__item__init(item);

    memset(&jitter, 0, sizeof(jitter));

    item->n_loss_periods = 0;
    item->loss_periods = NULL;

    for ( i = 0; i < options->packet_count; i++ ) {
        //XXX this check doesn't properly work to prevent unset timevals?
        if ( !timerisset(&times[i]) ) {
            if ( period &&
                 period->status == AMPLET2__UDPSTREAM__PERIOD__STATUS__LOST ) {
                period->length++;
            } else {
                /* create a new period after the current one */
                item->loss_periods =
                    realloc(item->loss_periods, (item->n_loss_periods+1) *
                            sizeof(Amplet2__Udpstream__Period*));

                period = item->loss_periods[item->n_loss_periods] =
                    new_loss_period(AMPLET2__UDPSTREAM__PERIOD__STATUS__LOST);

                item->n_loss_periods++;
                loss_runs++;
            }
            continue;
        }

        /* packet was received ok, and has a timestamp */
        received++;

        if ( period &&
             period->status == AMPLET2__UDPSTREAM__PERIOD__STATUS__RECEIVED ) {
            period->length++;
        } else {
            /* create a new period after the current one */
            item->loss_periods =
                realloc(item->loss_periods, (item->n_loss_periods+1) *
                        sizeof(Amplet2__Udpstream__Period*));

            period = item->loss_periods[item->n_loss_periods] =
                new_loss_period(AMPLET2__UDPSTREAM__PERIOD__STATUS__RECEIVED);

            item->n_loss_periods++;
        }

        if ( received == 1 ) {
            prev = (times[i].tv_sec * 1000000) + times[i].tv_usec;
            continue;
        }

        current = (times[i].tv_sec * 1000000) + times[i].tv_usec;

        ipdv[jitter.samples] = current - prev;
        prev = current;

        delta = (double)ipdv[jitter.samples] - mean;
        jitter.samples++;
        mean += delta / jitter.samples;
    }

    Log(LOG_DEBUG, "Packets received: %d", received);
    Log(LOG_DEBUG, "Loss periods: %d", item->n_loss_periods);

    /* every result will have these, even if no packets were received */
    item->has_direction = 1;
    item->direction = direction;
    item->has_packets_received = 1;
    item->packets_received = received;
    item->has_loss_percent = 1;
    item->loss_percent = 100 - ((double)item->packets_received /
            (double)options->packet_count*100);


    /* no useful delay variance, not enough packets arrived */
    if ( jitter.samples == 0 ) {
        return item;
    }

    /* at least two packets arrived - we have one delay variance measurement */
    qsort(&ipdv, jitter.samples, sizeof(int32_t), cmp);
    jitter.maximum = ipdv[jitter.samples - 1];
    jitter.minimum = ipdv[0];
    jitter.mean = mean;
    item->jitter = report_summary(&jitter);

    /*
     * Base the number of percentiles around the minimum of what the user
     * wanted, and the number of measurements we have. We might be duplicating
     * data by including the min/max here as well, but it makes life easier.
     */
    item->n_percentiles = MIN(options->percentile_count, jitter.samples);
    item->percentiles = calloc(item->n_percentiles, sizeof(int32_t));

    Log(LOG_DEBUG, "Reporting %d percentiles", item->n_percentiles);

    for ( i = 0; i < item->n_percentiles; i++ ) {
        Log(LOG_DEBUG, "Percentile %d (%d): %d\n", (i+1) * 10,
                (int)(jitter.samples / item->n_percentiles * (i+1)) - 1,
                ipdv[(int)(jitter.samples / item->n_percentiles * (i+1)) - 1]);
        item->percentiles[i] = ipdv[(int)
            (jitter.samples / item->n_percentiles * (i+1)) - 1];
    }

    /*
     * If we have an rtt then we can calculate MOS scores. This will generally
     * only happen on the client before reporting because the server doesn't
     * have enough information to do so.
     */
    if ( rtt ) {
        item->rtt = report_summary(rtt);
        item->voip = report_voip(item);
    }

    return item;
}
