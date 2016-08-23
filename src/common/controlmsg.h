#ifndef _COMMON_CONTROLMSG_H
#define _COMMON_CONTROLMSG_H

#include <stdint.h>
#include <openssl/bio.h>
#include <google/protobuf-c/protobuf-c.h>

#include "tests.h"

/* TODO this should be adjusted based on the expected test duration? Short when
 * exchanging messages, longer when waiting for test results. Or should the
 * remote client program just call read multiple times till it hits the
 * expected duration?
 */
#define CONTROL_CONNECTION_TIMEOUT 60

/* arbitrary cap to make sure massive amounts of memory aren't allocated */
#define MAX_CONTROL_MESSAGE_SIZE (1024 * 1024 * 10)


int write_control_packet(BIO *ctrl, void *data, uint32_t len);
int read_control_packet(BIO *ctrl, void **data);

int send_control_hello(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_ready(test_type_t test, BIO *ctrl, uint16_t port);
int send_control_receive(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_send(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_result(test_type_t test, BIO *ctrl, ProtobufCBinaryData *data);
//XXX throughput specific
int send_control_renew(test_type_t test, BIO *ctrl);

int read_control_hello(test_type_t test, BIO *ctrl, void **options,
        void *(*parse_func)(ProtobufCBinaryData *data));
int read_control_ready(test_type_t test, BIO *ctrl, uint16_t *port);
int read_control_result(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *results);

/* extract data from send/receive for remote servers (udp, throughput) */
int parse_control_receive(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_send(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));

#endif
