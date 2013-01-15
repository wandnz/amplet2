#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>

#include <stdint.h>

#include "messaging.h"
#include "debug.h"


/*
 * Create a connection to the local broker that measured can use to report
 * data for all tests. Each test will use a different channel within this
 * connection (sharing channels leads to broken behaviour). This will persist 
 * for the lifetime of measured.
 * TODO can we detect this going away and reconnect if it does so?
 */
int connect_to_broker() {
    int sock;

    /* this connection will be held open forever while measured runs */
    Log(LOG_DEBUG, "Opening new connection to broker on %s:%d\n",
	    AMQP_SERVER, AMQP_PORT);

    conn = amqp_new_connection();
    if ( (sock = amqp_open_socket(AMQP_SERVER, AMQP_PORT)) < 0 ) {
	Log(LOG_ERR, "Failed to open socket to broker %s:%d",
		AMQP_SERVER, AMQP_PORT);
	return -1;
    }
    
    amqp_set_sockfd(conn, sock);

    /* login to the broker */
    /* TODO use a better auth mechanism than plain SASL with guest/guest */
    if ( (amqp_login(conn, "/", 0, AMQP_FRAME_MAX, 0, AMQP_SASL_METHOD_PLAIN, 
	    "guest", "guest")).reply_type != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to login to broker");
	return -1;
    }

    return 0;
}



/*
 * Report results for a single test to the local broker. 
 *
 * example amqp_table_t stuff:
 * https://groups.google.com/forum/?fromgroups=#!topic/rabbitmq-discuss/M_8I12gWxbQ
 * root@machine4:~/rabbitmq/rabbitmq-c/tests/test_tables.c
 */
int report_to_broker(uint64_t timestamp, size_t len, void *bytes) {
    amqp_basic_properties_t props;
    amqp_bytes_t data;
    amqp_table_t headers;
    amqp_table_entry_t table_entries[2];

    /* 
     * open a new channel for every reporting process, there may be multiple
     * of these going on at once so they need individual channels
     */
    Log(LOG_DEBUG, "Opening new channel %d to broker\n", getpid());
    amqp_channel_open(conn, getpid());

    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to open channel");
	return -1;
    }

    /*
     * Add all the headers to describe the data we are sending:
     *	- source monitor
     *	- test type
     *	- timestamp? already a property, but i need to set
     */

    /* The name of the reporting monitor (our local ampname) */
    table_entries[0].key = amqp_cstring_bytes("x-amp-source-monitor");
    table_entries[0].value.kind = AMQP_FIELD_KIND_UTF8;
    table_entries[0].value.value.bytes = amqp_cstring_bytes("amp-machine8");
    
    /* The name of the test data is being reported for */
    table_entries[1].key = amqp_cstring_bytes("x-amp-test-type");
    table_entries[1].value.kind = AMQP_FIELD_KIND_UTF8;
    table_entries[1].value.value.bytes = amqp_cstring_bytes("icmp");

    /* Add all the individual headers to the header table */
    headers.num_entries = 2;
    headers.entries = (amqp_table_entry_t *) calloc(headers.num_entries, 
	    sizeof(amqp_table_entry_t));
    headers.entries = table_entries;

    /* Mark the flags that will be present */
    props._flags = 
	AMQP_BASIC_CONTENT_TYPE_FLAG | 
	AMQP_BASIC_DELIVERY_MODE_FLAG |
	AMQP_BASIC_HEADERS_FLAG |
	AMQP_BASIC_TIMESTAMP_FLAG;

    props.content_type = amqp_cstring_bytes("application/octet-stream");
    props.delivery_mode = 2; /* persistent delivery mode */
    props.headers = headers;
    props.timestamp = timestamp;

    /* TODO how to format message? what protocol to use for it? */
    /* jump dump a binary blob similar to old style? */
    data.len = len;
    data.bytes = bytes;

    /* TODO use proper exchange, routing keys, etc */
    /* publish the message */
    Log(LOG_DEBUG, "Publishing message\n");
    if ( amqp_basic_publish(conn,
	    getpid(),				    /* channel, our pid */
	    amqp_cstring_bytes("amp_exchange"),	    /* exchange name */
	    amqp_cstring_bytes("test"),		    /* routing key */
	    0,					    /* mandatory */
	    0,					    /* immediate */
	    &props,				    /* properties */
	    data) < 0 ) {			    /* body */

	Log(LOG_ERR, "Failed to publish message");
	return -1;
    }

    /* TODO do something if publishing fails? */
    Log(LOG_DEBUG, "Closing channel %d\n", getpid());

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
