#ifndef _COMMON_MESSAGING_H
#define _COMMON_MESSAGING_H

#include <amqp.h>
#include <amqp_framing.h>
#include "tests.h"


/* local broker will persist it for us and send to master server later */
#define AMQP_SERVER "localhost"

/* 5672 is default, 5671 for SSL */
#define AMQP_PORT 5672

/* vhost "/" is the default */
#define AMQP_VHOST "/"

/* 128KB, recommended default */
#define AMQP_FRAME_MAX 131072

/* exchange and routing key used to report to the local broker */
#define AMQP_LOCAL_EXCHANGE ""
#define AMQP_LOCAL_ROUTING_KEY "report"


amqp_connection_state_t conn;


int connect_to_broker(void);
void close_broker_connection(void);
int report_to_broker(test_type_t type, amp_test_result_t *result);

#endif
