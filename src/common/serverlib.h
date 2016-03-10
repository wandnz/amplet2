#ifndef _COMMON_SERVERLIB_H
#define _COMMON_SERVERLIB_H

#include "tests.h"
#include "testlib.h"


#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#define MAXIMUM_SERVER_WAIT_TIME 60000000

enum ctrlstream_type {
    PLAIN_CONTROL_STREAM,
    SSL_CONTROL_STREAM,
};

struct ctrlstream {
    enum ctrlstream_type type;
    union {
        int sock;
        SSL *ssl;
    } stream;
};


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


int write_control_packet(struct ctrlstream *ctrl, void *data, uint32_t len);
int read_control_packet(struct ctrlstream *ctrl, void **data);
int write_control_packet_ssl(SSL *ssl, void *data, uint32_t len);
int read_control_packet_ssl(SSL *ssl, void **data);

int send_control_hello(test_type_t test, struct ctrlstream *ctrl,
        ProtobufCBinaryData *options);
int send_control_ready(test_type_t test, struct ctrlstream *ctrl,uint16_t port);
int send_control_receive(test_type_t test, struct ctrlstream *ctrl,
        ProtobufCBinaryData *options);
int send_control_send(test_type_t test, struct ctrlstream *ctrl,
        ProtobufCBinaryData *options);
int send_control_result(test_type_t test, struct ctrlstream *ctrl,
        ProtobufCBinaryData *data);
//XXX throughput specific
int send_control_renew(test_type_t test, struct ctrlstream *ctrl);

int read_control_hello(test_type_t test, struct ctrlstream *ctrl,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int read_control_ready(test_type_t test, struct ctrlstream *ctrl,
        uint16_t *port);
//int read_control_packet(int sock, void **data);
int read_control_result(test_type_t test, struct ctrlstream *ctrl,
        ProtobufCBinaryData *results);

/* XXX how many parse functions can be static? */
int parse_control_hello(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_ready(test_type_t test, void *data, uint32_t len,
        uint16_t *port);
int parse_control_receive(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_send(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));

struct addrinfo *get_socket_address(int sock);
int start_listening(struct socket_t *sockets, int port,
        struct sockopt_t *sockopts);
int connect_to_server(struct addrinfo *server, struct sockopt_t *options, int port);

#endif
