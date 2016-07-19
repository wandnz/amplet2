#ifndef _MEASURED_MESSAGING_H
#define _MEASURED_MESSAGING_H

#include <amqp.h>
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

/*
 * TODO: this should be maintained for the lifetime of the main process, but
 * is currently just created and set by the individual test processes.
 */
amqp_connection_state_t conn;

int report_to_broker(test_type_t type, amp_test_result_t *result);

#endif
