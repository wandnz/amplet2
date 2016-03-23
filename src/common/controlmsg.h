#ifndef _COMMON_CONTROLMSG_H
#define _COMMON_CONTROLMSG_H

#include "tests.h"

#define CONTROL_CONNECTION_TIMEOUT 5


int write_control_packet(BIO *ctrl, void *data, uint32_t len);
int read_control_packet(BIO *ctrl, void **data);

int send_control_hello(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options);
int send_control_ready(test_type_t test, BIO *ctrl,uint16_t port);
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

/* XXX how many parse functions can be static? */
int parse_control_hello(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_ready(test_type_t test, void *data, uint32_t len,
        uint16_t *port);
int parse_control_receive(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));
int parse_control_send(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data));

#endif
