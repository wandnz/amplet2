#ifndef MEASURED_TESTLIB_H
#define MEASURED_TESTLIB_H

/* minimum time in usec allowed between sending test packets */
#define MIN_INTER_PACKET_DELAY 100

#define US_FROM_US(x) ((x) % 1000000)
#define S_FROM_US(x)  ((int)((x)/1000000))
#define DIFF_TV_US(tva, tvb) ( (((tva).tv_sec - (tvb).tv_sec) * 1000000) + \
                              ((tva).tv_usec - (tvb).tv_usec) )

/*
 * Structure combining the ipv4 and ipv6 network sockets so that they can be
 * passed around and operated on together as a single item.
 */
struct socket_t {
    int socket;                 /* ipv4 socket, if available */
    int socket6;                /* ipv6 socket, if available */
};

int get_packet(struct socket_t *sockets, char *buf, int len,
	struct sockaddr *saddr, int *timeout);

int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest);

#endif
