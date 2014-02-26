#ifndef _MEASURED_TESTLIB_H
#define _MEASURED_TESTLIB_H

#include "tests.h"
#include "debug.h"

/*
 * maximum length of a string in a report - the python code uses one byte
 * to determine how much to read from the buffer
 */
#define MAX_STRING_FIELD 255

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

int wait_for_data(struct socket_t *sockets, int *maxwait);
int get_packet(struct socket_t *sockets, char *buf, int len,
	struct sockaddr *saddr, int *timeout);
int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest);
int report(test_type_t type, uint64_t timestamp, void *bytes, size_t len);
char *address_to_name(struct addrinfo *address);
uint16_t start_remote_server(test_type_t type, struct addrinfo *dest);
int send_server_port(SSL *ssl, uint16_t port);

#endif
