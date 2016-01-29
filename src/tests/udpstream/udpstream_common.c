#include <unistd.h>

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

    sleep(2);//XXX

    for ( i = 0; i < options->packet_count; i++ ) {
        //TODO update payload with packet number
        //TODO update payload with timestamp it was sent
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
    int timeout = 10000000;//XXX
    int bytes;
    int i;
    uint32_t id;
    struct timeval sent_time;

    struct socket_t sockets;//XXX
    sockets.socket = sock;//XXX
    sockets.socket6 = -1;//XXX

    printf("receive udp stream\n");

    //XXX never gets freed
    //times = calloc(packet_count, sizeof(struct timeval));

    for ( i = 0; i < packet_count; i++ ) {
        printf("waiting for %d\n", i);
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




