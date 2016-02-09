#ifndef _COMMON_SERVERLIB_H
#define _COMMON_SERVERLIB_H

#include "tests.h"
#include "testlib.h"


#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#define MAXIMUM_SERVER_WAIT_TIME 60000000


struct temp_sockopt_t_xxx {
    struct addrinfo *sourcev4;
    struct addrinfo *sourcev6;
    int socktype;
    int protocol;
    uint16_t cport; // XXX both ports probably not needed in same struct?
    uint16_t tport;
    char *device;
    uint16_t packet_size;
    uint32_t packet_count;
    uint32_t packet_spacing; //XXX inter_packet_delay;
    uint32_t percentile_count;

    //XXX test opts
    int32_t sock_mss; /* Set the TCP Maximun segment size */
    uint8_t sock_disable_nagle;
    uint8_t reuse_addr;
    int32_t sock_rcvbuf;
    int32_t sock_sndbuf;
    uint8_t randomise;
    uint8_t disable_web10g;
};


int send_control_hello(int sock_fd, struct temp_sockopt_t_xxx *options);
int send_control_ready(int sock, uint16_t port);
int send_control_receive(int sock, uint32_t packet_count);
int send_control_send(int sock, uint16_t port);
int send_control_result(int sock, ProtobufCBinaryData *data);

int read_control_hello(int sock, struct temp_sockopt_t_xxx *options);
int read_control_ready(int sock, struct temp_sockopt_t_xxx *options);
int read_control_packet(int sock, void **data);
int read_control_result(int sock, ProtobufCBinaryData *results);

int parse_control_hello(void *data, uint32_t len,
        struct temp_sockopt_t_xxx *options);
int parse_control_ready(void *data, uint32_t len,
        struct temp_sockopt_t_xxx *options);
int parse_control_receive(void *data, uint32_t len,
        struct temp_sockopt_t_xxx *options);

int start_listening(struct socket_t *sockets, int port,
        struct temp_sockopt_t_xxx *sockopts);
int connect_to_server(struct addrinfo *server, struct temp_sockopt_t_xxx *options, int port);

#endif
