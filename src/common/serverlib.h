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


struct addrinfo *get_socket_address(int sock);
int start_listening(struct socket_t *sockets, int port,
        struct sockopt_t *sockopts);
int connect_to_server(struct addrinfo *server, struct sockopt_t *options, int port);
BIO* listen_control_server(uint16_t port, uint16_t portmax,
        struct sockopt_t *sockopts);
int start_remote_server(BIO *ctrl, test_type_t type);
BIO* connect_control_server(struct addrinfo *dest, uint16_t port,
        amp_test_meta_t *meta);
void close_control_connection(BIO *ctrl);

#endif
