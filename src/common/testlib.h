#ifndef _MEASURED_TESTLIB_H
#define _MEASURED_TESTLIB_H

#include <google/protobuf-c/protobuf-c.h>

#include "tests.h"
#include "debug.h"

/*
 * maximum length of a string in a report - the python code uses one byte
 * to determine how much to read from the buffer
 */
#define MAX_STRING_FIELD 255

/* minimum time in usec allowed between sending test packets */
#define MIN_INTER_PACKET_DELAY 100

/* max number of attempts to make when retrying control connections */
#define MAX_CONNECT_ATTEMPTS 3
/* time in seconds to wait between attempts to establish control connects */
#define CONTROL_CONNECT_DELAY 2

#define US_FROM_US(x) ((x) % 1000000)
#define S_FROM_US(x)  ((int)((x)/1000000))
#define DIFF_TV_US(tva, tvb) ( (((tva).tv_sec - (tvb).tv_sec) * 1000000) + \
                              ((tva).tv_usec - (tvb).tv_usec) )

/*
 * this is all from endian.h and byteswap.h in libc >= 2.9, lenny doesn't
 * provide these, so lets put them here till we can abandon lenny.
 */
#ifndef htobe64
#include <endian.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe16(x) __bswap_16 (x)
#  define htole16(x) (x)
#  define be16toh(x) __bswap_16 (x)
#  define le16toh(x) (x)

#  define htobe32(x) __bswap_32 (x)
#  define htole32(x) (x)
#  define be32toh(x) __bswap_32 (x)
#  define le32toh(x) (x)

#  define htobe64(x) __bswap_64 (x)
#  define htole64(x) (x)
#  define be64toh(x) __bswap_64 (x)
#  define le64toh(x) (x)
# else
#  define htobe16(x) (x)
#  define htole16(x) __bswap_16 (x)
#  define be16toh(x) (x)
#  define le16toh(x) __bswap_16 (x)

#  define htobe32(x) (x)
#  define htole32(x) __bswap_32 (x)
#  define be32toh(x) (x)
#  define le32toh(x) __bswap_32 (x)

#  define htobe64(x) (x)
#  define htole64(x) __bswap_64 (x)
#  define be64toh(x) (x)
#  define le64toh(x) __bswap_64 (x)
# endif

#endif

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
	struct sockaddr *saddr, int *timeout, struct timeval *now);
int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest,
        uint32_t inter_packet_delay, struct timeval *sent);
char *address_to_name(struct addrinfo *address);
int compare_addresses(const struct sockaddr *a,
        const struct sockaddr *b, int len);
int start_remote_server(SSL *ssl, test_type_t type);
//uint16_t start_remote_server(test_type_t type, struct addrinfo *dest,
//        amp_test_meta_t *meta);
struct ctrlstream* connect_control_server(struct addrinfo *dest, uint16_t port,
        amp_test_meta_t *meta);
void close_control_connection(struct ctrlstream *ctrl);
int send_server_port(SSL *ssl, uint16_t port);
struct addrinfo *get_numeric_address(char *interface, char *port);
int bind_socket_to_device(int sock, char *device);
int bind_sockets_to_device(struct socket_t *sockets, char *device);
int bind_socket_to_address(int sock, struct addrinfo *address);
int bind_sockets_to_address(struct socket_t *sockets,
        struct addrinfo *sourcev4, struct addrinfo *sourcev6);
int set_default_socket_options(struct socket_t *sockets);
int check_exists(char *path, int strict);
int copy_address_to_protobuf(ProtobufCBinaryData *dst,
        const struct addrinfo *src);

#endif
