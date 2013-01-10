#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>

#include <stdint.h>

#include "messaging.h"
#include "debug.h"


/*
 * TODO more and better error checking/reporting
 */

/*
 * Create a connection to the local broker that measured can use to report
 * data for all tests. Each test will use a different channel within this
 * connection (sharing channels leads to broken behaviour). This will persist 
 * for the lifetime of measured.
 * TODO can we detect this going away and reconnect if it does so?
 */
int connect_to_broker() {
    //amqp_connection_state_t conn;
    int sock;

    /* this connection will be held open forever while measured runs */
    fprintf(stderr, "new connection to broker\n");
    conn = amqp_new_connection();
    fprintf(stderr, "about to open socket\n");
    if ( (sock = amqp_open_socket(AMQP_SERVER, AMQP_PORT)) < 0 ) {
	Log(LOG_ERR, "Failed to open socket to broker");
	return -1;
    }
    fprintf(stderr, "about to set socket\n");
    amqp_set_sockfd(conn, sock);

    /* login to the broker */
    /* TODO use a better auth mechanism than plain SASL with guest/guest */
    fprintf(stderr, "about to log in\n");
    if ( (amqp_login(conn, "/", 0, AMQP_FRAME_MAX, 0, AMQP_SASL_METHOD_PLAIN, 
	    "guest", "guest")).reply_type != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to login to broker");
	return -1;
    }

    fprintf(stderr, "conn=%p\n", conn);

    return 0;
}



/*
 * TODO determine where to put things into a known format (and which format)
 * Report results for a single test to the local broker. 
 */
int report_to_broker(/*amqp_connection_state_t conn*/size_t len, void *bytes) {
    amqp_basic_properties_t props;
    amqp_bytes_t data;

    /* 
     * open a new channel for every reporting process, there may be multiple
     * of these going on at once so they need individual channels
     */
    fprintf(stderr, "opening channel\n");
    fprintf(stderr, "con=%p, channel=%d\n", conn, getpid());
    amqp_channel_open(conn, getpid());

    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to open channel");
	return -1;
    }

    /* mark the flags that should be checked? */
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("text/plain");
    props.delivery_mode = 2; /* persistent delivery mode */

    /* TODO how to format message? what protocol to use for it? */
    //data = amqp_bytes_malloc(sizeof(uint32_t));
    //memcpy(data.bytes, &foo, sizeof(uint32_t));
    data.len = len;
    data.bytes = bytes;

    /* publish the message */
    /* TODO use proper exchange, routing keys, etc */
    fprintf(stderr, "publishing\n");
    if ( amqp_basic_publish(conn,
	    getpid(),				    /* channel, our pid */
	    //amqp_cstring_bytes("amq.direct"),	    /* exchange name */
	    amqp_cstring_bytes("amp_exchange"),	    /* exchange name */
	    amqp_cstring_bytes("test"),		    /* routing key */
	    0,					    /* mandatory */
	    0,					    /* immediate */
	    &props,				    /* properties */
	    //amqp_cstring_bytes("foobar")) < 0 ) {   /* body */
	    data) < 0 ) {   /* body */

	Log(LOG_ERR, "Failed to publish");
	return -1;
    }

    /* TODO do something if publishing fails? */
    fprintf(stderr, "closing channel\n");

    amqp_channel_close(conn, getpid(), AMQP_REPLY_SUCCESS);

    return 0;
}



/*
 * Close the connection to the local broker. Should only be called when
 * measured is terminating.
 */
void close_broker_connection() {
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
}
