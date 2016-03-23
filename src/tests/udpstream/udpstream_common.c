#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <string.h>

#include "serverlib.h"
#include "udpstream.h"
#include "debug.h"



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

    data->len = amplet2__udpstream__hello__get_packed_size(&hello);
    data->data = malloc(data->len);
    amplet2__udpstream__hello__pack(&hello, data->data);

    return data;
}



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

    amplet2__udpstream__hello__free_unpacked(hello, NULL);

    return options;
}



/*
 * XXX take options structure or integer?
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
 * XXX return options structure or integer? integer might be easier
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
int send_udp_stream(int sock, struct addrinfo *remote, struct opt_t *options) {
    struct timeval now;
    struct payload_t *payload;
    uint32_t i;
    size_t payload_len;

    Log(LOG_DEBUG, "Sending UDP stream, packets:%d size:%d spacing:%d",
            options->packet_count, options->packet_size,
            options->packet_spacing);

    //XXX put a pattern in the payload?
    /* the packet size option includes headers, so subtract them */
    if ( remote->ai_family == AF_INET ) {
        payload_len = options->packet_size - sizeof(struct iphdr);
    } else {
        payload_len = options->packet_size - sizeof(struct ip6_hdr);
    }

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
            return -1;
        }

        /* TODO not accurate, but good enough for now */
        usleep(options->packet_spacing);
    }

    free(payload);

    return 0;
}



/*
 * XXX packet_count or a full options struct?
 * Receive a stream of UDP packets, expecting the specified number of packets.
 */
int receive_udp_stream(int sock, uint32_t packet_count, struct timeval *times) {
    char buffer[4096];//XXX
    int timeout;
    uint32_t i;
    struct timeval sent_time;
    struct socket_t sockets;
    struct payload_t *payload;

    /*
     * TODO not ideal, but just put the same socket in both slots, unless we
     * really feel like working out the address family
     */
    sockets.socket = sock;
    sockets.socket6 = sock;

    Log(LOG_DEBUG, "Receiving UDP stream, packets:%d", packet_count);

    for ( i = 0; i < packet_count; i++ ) {
        /* reset timeout per packet, consider some global timer also? */
        timeout = UDPSTREAM_LOSS_TIMEOUT;

        if ( get_packet(&sockets, buffer, sizeof(buffer), NULL,
                    &timeout, &times[i]) > 0 ) {
            payload = (struct payload_t*)&buffer;
            /* this should cast appropriately whether 32 or 64 bit */
            sent_time.tv_sec = (time_t)be64toh(payload->sec);
            sent_time.tv_usec = (time_t)be64toh(payload->usec);
            timersub(&times[i], &sent_time, &times[i]);
            Log(LOG_DEBUG, "Got UDP stream packet %d (id:%d)", i,
                    ntohl(payload->index));
            /* TODO check that the packet belongs to our stream */
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
 *
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
 *
 */
Amplet2__Udpstream__Item* report_stream(enum udpstream_direction direction,
        struct timeval *times, struct opt_t *options) {
    Amplet2__Udpstream__Item *item =
        (Amplet2__Udpstream__Item*)malloc(sizeof(Amplet2__Udpstream__Item));
    uint32_t i;
    uint32_t count = 0, received = 0;
    int32_t current = 0, prev = 0;
    int32_t ipdv[options->packet_count];
    Amplet2__Udpstream__Period *period = NULL;

    Log(LOG_DEBUG, "Reporting udpstream results");

    amplet2__udpstream__item__init(item);

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

        ipdv[count] = current - prev;

        prev = current;
        count++;
    }

    qsort(&ipdv, count, sizeof(int32_t), cmp);

    Log(LOG_DEBUG, "Packets received: %d", received);
    Log(LOG_DEBUG, "Loss periods: %d", item->n_loss_periods);

    /* every result will have these, even if no packets were received */
    item->has_direction = 1;
    item->direction = direction;
    item->has_packets_received = 1;
    item->packets_received = received;

    /* no useful delay variance, not enough packets arrived */
    if ( count == 0 ) {
        return item;
    }

    /* at least two packets arrived - we have one delay variance measurement */
    item->has_maximum = 1;
    item->maximum = ipdv[count -1];
    item->has_minimum = 1;
    item->minimum = ipdv[0];

    item->has_median = 1;
    if ( count % 2 ) {
        /* odd number of results, take the middle one */
        item->median = ipdv[count / 2];
    } else {
        /* round up the difference in the middle values, so we get an integer */
        item->median = (ipdv[count / 2] + ipdv[(count / 2) - 1]) / 2;
    }

    /*
     * Base the number of percentiles around the minimum of what the user
     * wanted, and the number of measurements we have. We might be duplicating
     * data by including the min/max here as well, but it makes life easier.
     */
    item->n_percentiles = MIN(options->percentile_count, count);
    item->percentiles = calloc(item->n_percentiles, sizeof(int32_t));

    Log(LOG_DEBUG, "Reporting %d percentiles", item->n_percentiles);

    for ( i = 0; i < item->n_percentiles; i++ ) {
        Log(LOG_DEBUG, "Percentile %d (%d): %d\n", (i+1) * 10,
                (int)(count / item->n_percentiles * (i+1)) - 1,
                ipdv[(int)(count / item->n_percentiles * (i+1)) - 1]);
        item->percentiles[i] = ipdv[(int)
            (count / item->n_percentiles * (i+1)) - 1];
    }

    return item;
}
