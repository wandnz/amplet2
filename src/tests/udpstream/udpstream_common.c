#include <unistd.h>

#include "serverlib.h"
#include "udpstream.h"


/*
 *
 */
int send_udp_stream(int sock, struct addrinfo *remote, struct opt_t *options) {
    struct timeval now;
    char *payload;
    uint32_t i;

    printf("send udp stream\n");

    //XXX put a pattern in the payload?
    payload = (char *)calloc(1, options->packet_size); //XXX subtract headers?

    for ( i = 0; i < options->packet_count; i++ ) {
        printf("sending %d\n", i);

        gettimeofday(&now, NULL);
        memcpy(payload, &i, sizeof(i));
        //XXX won't work on 32 bit machines with 32bit timevals
        memcpy(payload + sizeof(i), &now, sizeof(now));

        if ( sendto(sock, payload, options->packet_size, 0,
                    remote->ai_addr, remote->ai_addrlen) < 0 ) {
            Log(LOG_WARNING, "Error sending udpstream packet, aborting");
            return -1;
        }
        /* TODO not accurate, but good enough for now */
        usleep(options->packet_spacing);
    }

    return 0;
}



/*
 * XXX packet_count or a full options struct?
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

    printf("receive udp stream: %d packets\n", packet_count);

    //XXX never gets freed
    //times = calloc(packet_count, sizeof(struct timeval));

    for ( i = 0; i < packet_count; i++ ) {
        printf("waiting for %d\n", i);
        timeout = UDPSTREAM_LOSS_TIMEOUT;
        if ( (bytes = get_packet(&sockets, buffer, sizeof(buffer), NULL,
                    &timeout, &times[i])) > 0 ) {
            memcpy(&id, buffer, sizeof(id));
            memcpy(&sent_time, buffer + sizeof(id), sizeof(sent_time));
            printf("got packet %d (%d)\n", i, id);
            printf("%d.%d bytes = %d\n", times[i].tv_sec, times[i].tv_usec,
                    bytes);
            printf("%d.%d\n", sent_time.tv_sec, sent_time.tv_usec);
            timersub(&times[i], &sent_time, &times[i]);
            printf("%d.%06d\n", times[i].tv_sec, times[i].tv_usec);
        } else {
            printf("packet didn't arrive\n");
        }
    }

    return 0;
}



/*
 *
 */
static int cmp(const void *a, const void *b) {
    return ( *(uint32_t*)a - *(uint32_t*)b );
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
    int foo = 0;
    int32_t ipdv[options->packet_count];
    //int32_t percentiles[10];

    printf("report stream\n");

    //XXX do we want to know exactly which packets were dropped?
    for ( i = 0; i < options->packet_count; i++ ) {
        //XXX this check doesn't properly work to prevent unset timevals?
        if ( !timerisset(&times[i]) ) {
            continue;
        }

        received++;

        //if ( prev == NULL ) {
            //XXX won't work with loss
        if ( !foo ) {
            printf("%d %ld.%06ld\n", i, times[i].tv_sec, times[i].tv_usec);
            prev = (times[i].tv_sec * 1000000) + times[i].tv_usec;
            foo = 1;
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

    amplet2__udpstream__item__init(item);

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

    /* XXX 100% percentile is pointless */
    for ( i = 0; i < item->n_percentiles; i++ ) {
        printf("storing %d (%d): %d\n", i,
                (int)(count / item->n_percentiles * (i+1)) - 1,
                ipdv[(int)(count / item->n_percentiles * (i+1)) - 1]);
        item->percentiles[i] = ipdv[(int)
            (count / item->n_percentiles * (i+1)) - 1];
        //XXX of by one
    }


    item->has_direction = 1;
    item->direction = direction;
    item->has_maximum = 1;
    item->maximum = ipdv[count -1];
    item->has_minimum = 1;
    item->minimum = ipdv[0];
    item->has_median = 1;
    item->median = ipdv[count / 2];//XXX
    item->has_packets_received = 1;
    item->packets_received = received;
    //item->percentiles = percentiles;

    printf("item packed size: %d\n",
            amplet2__udpstream__item__get_packed_size(item));

    return item;
}
