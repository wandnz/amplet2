#ifndef _COMMON_SERVERLIB_H
#define _COMMON_SERVERLIB_H

#include "tests.h"
#include "testlib.h"


//XXX this should probably be a bit bigger
#define MAX_MALLOC 4096
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

enum UDPSTREAM_PKT {
    //UDPSTREAM_PACKET_HELLO = 0,
    //UDPSTREAM_PACKET_SEND = 1,
    UDPSTREAM_PACKET_RECEIVE = 2,
};

enum CONTROL_PACKET {
    CONTROL_PACKET_HELLO = 0,
    CONTROL_PACKET_READY = 1,
};

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
};

struct packet_t {
    struct header_t {
        uint32_t type;
        uint32_t size; /* Size excluding header sizeof(struct packet_t) */
    } header;
    //XXX TODO tidy this up and be more generic
    union type_t {
        struct helloPacket_t {
            uint32_t  version;
            uint16_t  tport;
            uint8_t   flags; /* web10g, nagle, randomise */
            uint8_t   flags2; /* unused empty space set to 0 */
            uint32_t  mss;
            int32_t   sock_rcvbuf;
            int32_t   sock_sndbuf;
        } hello;
        struct readyPacket_t {
            uint16_t tport;
        } ready;
    } types; //type union
}; //packet_t struct


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
