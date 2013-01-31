#ifndef _MEASURED_MESSAGING_H
#define _MEASURED_MESSAGING_H

#include <amqp.h>
#include <amqp_framing.h>


/* local broker will persist it for us and send to master server later */
/* TODO what if the server is not local? Needs to be configurable at runtime */
#define AMQP_SERVER "localhost"

/* 5672 is default, 5671 for SSL */
#define AMQP_PORT 5672

/* 128KB, recommended default */
#define AMQP_FRAME_MAX 131072


amqp_connection_state_t conn;


int connect_to_broker(void);
void close_broker_connection(void);

#endif
