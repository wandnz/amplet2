#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "serverlib.h"
#include "udpstream.h"



/*
 * Send a stream of UDP packets towards the remote target, with the given
 * test options (size, spacing and count).
 */
int send_udp_stream(int sock, struct addrinfo *remote, struct opt_t *options) {
    struct timeval now;
    char *payload;
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
    payload = (char *)calloc(1, payload_len);

    for ( i = 0; i < options->packet_count; i++ ) {
        gettimeofday(&now, NULL);
        memcpy(payload, &i, sizeof(i));
        //XXX could gettimeofday() straight into payload area
        //XXX won't work on 32 bit machines with 32bit timevals
        memcpy(payload + sizeof(i), &now, sizeof(now));

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
    int bytes;
    uint32_t i;
    uint32_t id;
    struct timeval sent_time;

    struct socket_t sockets;//XXX
    sockets.socket = sock;//XXX
    sockets.socket6 = -1;//XXX

    Log(LOG_DEBUG, "Receiving UDP stream, packets:%d", packet_count);

    for ( i = 0; i < packet_count; i++ ) {
        /* reset timeout per packet, consider some global timer also? */
        timeout = UDPSTREAM_LOSS_TIMEOUT;

        if ( (bytes = get_packet(&sockets, buffer, sizeof(buffer), NULL,
                    &timeout, &times[i])) > 0 ) {
            memcpy(&id, buffer, sizeof(id));
            memcpy(&sent_time, buffer + sizeof(id), sizeof(sent_time));
            timersub(&times[i], &sent_time, &times[i]);
            Log(LOG_DEBUG, "Got UDP stream packet %d (id:%d)", i, id);
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
    int32_t total_diff = 0;
    uint32_t count = 0, received = 0;
    int32_t current, prev;
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
                printf("loss++\n");
            } else {
                /* create a new period after the current one */
                item->loss_periods =
                    realloc(item->loss_periods, (item->n_loss_periods+1) *
                            sizeof(Amplet2__Udpstream__Period*));

                period = item->loss_periods[item->n_loss_periods] =
                    new_loss_period(AMPLET2__UDPSTREAM__PERIOD__STATUS__LOST);

                item->n_loss_periods++;
                printf("new loss period\n");
            }
            continue;
        }

        /* packet was received ok, and has a timestamp */
        received++;

        if ( period &&
             period->status == AMPLET2__UDPSTREAM__PERIOD__STATUS__RECEIVED ) {
            period->length++;
            printf("good++\n");
        } else {
            /* create a new period after the current one */
            item->loss_periods =
                realloc(item->loss_periods, (item->n_loss_periods+1) *
                        sizeof(Amplet2__Udpstream__Period*));

            period = item->loss_periods[item->n_loss_periods] =
                new_loss_period(AMPLET2__UDPSTREAM__PERIOD__STATUS__RECEIVED);

            item->n_loss_periods++;
            printf("new good period\n");
        }

        if ( received < 2 ) {
            printf("%d %ld.%06ld\n", i, times[i].tv_sec, times[i].tv_usec);
            prev = (times[i].tv_sec * 1000000) + times[i].tv_usec;
            continue;
        }

        current = (times[i].tv_sec * 1000000) + times[i].tv_usec;

        ipdv[count] = current - prev;
        total_diff += (current - prev);
        printf("%d ipdv %d\n", i, current - prev);

        prev = current;
        count++;
    }

    printf("--- %d / %d = %f ---\n", total_diff, count,
            ((double)total_diff) / ((double)count));

    qsort(&ipdv, count, sizeof(int32_t), cmp);
    for ( i = 0; i < count; i++ ) {
        printf(" ++ %d\n", ipdv[i]);
    }

    printf("LOSS PERIODS (%d):\n", item->n_loss_periods);
    for ( i = 0; i < item->n_loss_periods; i++ ) {
        printf("%d:%d\n", item->loss_periods[i]->length,
                item->loss_periods[i]->status);
    }

    /*
     * Base the number of percentiles around the minimum of what the user
     * wanted, and the number of measurements we have. Also we can get away
     * without sending the largest and smallest measurements because they are
     * already being sent.
     */
    //XXX very low numbers could overflow, prevent this
    item->n_percentiles = MIN(options->percentile_count - 1, count - 2);
    item->percentiles = calloc(item->n_percentiles, sizeof(int32_t));

    printf("options->percentile_count: %d\n", options->percentile_count);
    printf("count: %d\n", count);

    printf("report item: %p\n", item);
    printf("reporting %d percentiles\n", item->n_percentiles);

    for ( i = 0; i < item->n_percentiles; i++ ) {
        printf("storing %d (%d): %d\n", i,
                (int)(count / item->n_percentiles * (i+1)) - 1,
                ipdv[(int)(count / item->n_percentiles * (i+1)) - 1]);
        item->percentiles[i] = ipdv[(int)
            (count / item->n_percentiles * (i+1)) - 1];
    }

    item->has_direction = 1;
    item->direction = direction;
    item->has_maximum = 1;
    item->maximum = ipdv[count -1];
    item->has_minimum = 1;
    item->minimum = ipdv[0];
    item->has_median = 1;
    if ( count % 2 ) {
        /* round up the difference in the middle values, so we get an integer */
        item->median = (ipdv[count / 2] + ipdv[(count / 2) + 1]) / 2;
    } else {
        /* integer arithmetic and zero based arrays mean this is the middle */
        item->median = ipdv[count / 2];
    }
    item->has_packets_received = 1;
    item->packets_received = received;

    return item;
}
