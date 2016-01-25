#include "udpstream.h"


/*
 *
 */
int send_udp_stream(int sock, struct addrinfo *remote, struct opt_t *options) {
    char *payload;
    int i;

    printf("send udp stream\n");

    //XXX put a pattern in the payload?
    payload = (char *)calloc(1, options->packet_size); //XXX subtract headers?

    sleep(2);//XXX

    for ( i = 0; i < options->packet_count; i++ ) {
        //TODO update payload with packet number
        printf("sending %d\n", i);
        if ( sendto(sock, payload, options->packet_size, 0,
                    remote->ai_addr, remote->ai_addrlen) < 0 ) {
            Log(LOG_WARNING, "Error sending udpstream packet, aborting");
            return -1;
        }
        usleep(options->packet_spacing);
    }

    return 0;
}



/*
 *
 */
int receive_udp_stream(int sock) {
    struct timeval *times;
    char buffer[4096];//XXX
    int timeout = 10000000;//XXX
    int bytes;
    int i;

    struct socket_t sockets;//XXX
    sockets.socket = sock;//XXX
    sockets.socket6 = -1;//XXX

    int packet_count = 10;//XXX

    printf("receive udp stream\n");

    times = calloc(packet_count, sizeof(struct timeval));

    for ( i = 0; i < packet_count; i++ ) {
        printf("waiting for %d\n", i);
        if ( (bytes = get_packet(&sockets, buffer, sizeof(buffer), NULL,
                    &timeout, &times[i])) > 0 ) {
            //XXX times[i] might be wrong packet, wait to get id from payload
            printf("got packet %d\n", i);
        }
        printf("%d.%d bytes = %d\n", times[i].tv_sec, times[i].tv_usec, bytes);
    }

    return 0;
}




