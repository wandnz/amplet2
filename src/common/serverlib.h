#ifndef _COMMON_SERVERLIB_H
#define _COMMON_SERVERLIB_H

#include "tests.h"
#include "testlib.h"


#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#define MAXIMUM_SERVER_WAIT_TIME 60000000


struct sockopt_t {
    struct addrinfo *sourcev4;
    struct addrinfo *sourcev6;
    int socktype;
    int protocol;
    char *device;

    int32_t sock_mss;
    uint8_t sock_disable_nagle;
    uint8_t reuse_addr;
    int32_t sock_rcvbuf;
    int32_t sock_sndbuf;
};



int send_control_hello(int sock, ProtobufCBinaryData *options);
int send_control_ready(int sock, uint16_t port);
int send_control_receive(int sock, ProtobufCBinaryData *options);
int send_control_send(int sock, ProtobufCBinaryData *options);
int send_control_result(int sock, ProtobufCBinaryData *data);
int send_control_renew(int sock);//XXX throughput specific

int read_control_hello(int sock, void **options,
        void *(*parse_func)(ProtobufCBinaryData *data));
int read_control_ready(int sock, uint16_t *port);
int read_control_packet(int sock, void **data);
int read_control_result(int sock, ProtobufCBinaryData *results);

/* XXX how many parse functions can be static? */
int parse_control_hello(void *data, uint32_t len, void **options,
        void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_ready(void *data, uint32_t len, uint16_t *port);
int parse_control_receive(void *data, uint32_t len, void **options,
        void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_send(void *data, uint32_t len, void **options,
        void *(*parse_func)(ProtobufCBinaryData *data));

struct addrinfo *get_socket_address(int sock);
int start_listening(struct socket_t *sockets, int port,
        struct sockopt_t *sockopts);
int connect_to_server(struct addrinfo *server, struct sockopt_t *options, int port);

#endif
