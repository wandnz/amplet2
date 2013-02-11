#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include <amqp.h>
#include <amqp_framing.h>

#include "debug.h"
#include "messaging.h"
#include "tests.h"
#include "consumer.h"
#include "modules.h"



/*
 * Open a new channel to the broker for us to communicate over.
 */
void setup_channel() {
    Log(LOG_DEBUG, "Opening new channel %d to broker\n", getpid());
    amqp_channel_open(conn, getpid());

    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to open channel");
	//return -1;
    }
}



/*
 *
 */
int setup_queue(char *name) {
    amqp_bytes_t queuename;

    assert(name); 

    queuename = amqp_cstring_bytes(name);;

    /* 
       AMQP_CALL amqp_queue_declare(
	   amqp_connection_state_t state, 
	   amqp_channel_t channel, 
	   amqp_bytes_t queue, 
	   amqp_boolean_t passive, 
	   amqp_boolean_t durable, 
	   amqp_boolean_t exclusive, 
	   amqp_boolean_t auto_delete, 
	   amqp_table_t arguments);
     */
    /* Declare the queue, all consumers should use the same one? */
    amqp_queue_declare_ok_t *r = amqp_queue_declare(conn, getpid(), 
	    queuename, 0, 1, 0, 0, amqp_empty_table);
    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to declare queue");
	//return -1;
    }

    /* Bind queue with the routing key, all consumers should use the same? */
    amqp_queue_bind(conn, getpid(), queuename, 
	    amqp_cstring_bytes("amp_exchange"), amqp_cstring_bytes("test"),
	    amqp_empty_table);
    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to bind queue");
	//return -1;
    }
    
    /* qos(connection, channel, prefetch-size, prefetch-count, global) */
    /* Limit each consumer to a single outstanding request */
    amqp_basic_qos(conn, getpid(), 0, 1, 0);

    /* Declare us as a consumer on this queue */
    /*
       amqp_basic_consume (   
	    amqp_connection_state_t state,
	    amqp_channel_t channel,
	    amqp_bytes_t queue,
	    amqp_bytes_t consumer_tag,
	    amqp_boolean_t no_local,
	    amqp_boolean_t no_ack,
	    amqp_boolean_t exclusive,
	    amqp_table_t arguments 
     */
    amqp_basic_consume(conn, getpid(), queuename, amqp_empty_bytes, 0, 0, 0, 
	    amqp_empty_table);
    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to start consuming");
	//return -1;
    }

    return 0;
}



/*
 *
 */
int consumer() {
    amqp_frame_t frame;
    int result;
    amqp_basic_deliver_t *d;
    amqp_basic_properties_t *p;
    size_t body_target;
    size_t body_received;
    char *monitor = NULL;
    char *test_type = NULL;
    char *buffer = NULL;
    test_type_t test_id;
    test_t *test;

    setup_channel();
    setup_queue("foo1");

    while ( running ) {
	amqp_maybe_release_buffers(conn);
	result = amqp_simple_wait_frame(conn, &frame);
	if (result < 0)
	    break;

	if (frame.frame_type != AMQP_FRAME_METHOD)
	    continue;

	if (frame.payload.method.id != AMQP_BASIC_DELIVER_METHOD)
	    continue;

	d = (amqp_basic_deliver_t *) frame.payload.method.decoded;
	Log(LOG_DEBUG, "Got message, exchange:%.*s routingkey:%.*s\n",
		(int) d->exchange.len, (char *) d->exchange.bytes,
		(int) d->routing_key.len, (char *) d->routing_key.bytes);

	result = amqp_simple_wait_frame(conn, &frame);
	if (result < 0)
	    break;

	if (frame.frame_type != AMQP_FRAME_HEADER) {
	    fprintf(stderr, "Expected header!");
	    exit(-1);
	}
	p = (amqp_basic_properties_t *) frame.payload.properties.decoded;

	/* find all the headers that we are interested in */
	if ( p->_flags & AMQP_BASIC_HEADERS_FLAG ) {
	    int i;
	    amqp_table_t headers = p->headers;
	    for ( i=0; i<headers.num_entries; i++ ) {
		if ( strncmp((char *)headers.entries[i].key.bytes, 
			    "x-amp-source-monitor",
			    (int)headers.entries[i].key.len) == 0 ) {
		    monitor = strndup((char *)
			    headers.entries[i].value.value.bytes.bytes, 
			    (int)headers.entries[i].value.value.bytes.len);
		} else if ( strncmp((char *)headers.entries[i].key.bytes,
			"x-amp-test-type",
			    (int)headers.entries[i].key.len) == 0 ) {
		    test_type = strndup((char *)
			    headers.entries[i].value.value.bytes.bytes, 
			    (int)headers.entries[i].value.value.bytes.len);
		}
	    }
	}

	/* TODO actual check - what to do if no timestamp? */
	if ( (p->_flags & AMQP_BASIC_TIMESTAMP_FLAG) == 0 ) {
	    printf("not a valid data packet, missing timestamp\n");
	    break;
	}

	body_target = frame.payload.properties.body_size;
	body_received = 0;
	/* XXX do we want to blindly trust this number? */
	buffer = malloc(body_target);

	while (body_received < body_target) {
	    result = amqp_simple_wait_frame(conn, &frame);
	    if (result < 0)
		break;

	    if (frame.frame_type != AMQP_FRAME_BODY) {
		fprintf(stderr, "Expected body!");
		abort();
	    }

	    /* copy the body fragment into our local buffer */
	    memcpy(&buffer[body_received], frame.payload.body_fragment.bytes,
		    frame.payload.body_fragment.len);
	    body_received += frame.payload.body_fragment.len;
	    assert(body_received <= body_target);
	}

	if (body_received != body_target) {
	    /* Can only happen when amqp_simple_wait_frame returns <= 0 */
	    /* We break here to close the connection */
	    free(monitor);
	    free(test_type);
	    free(buffer);
	    break;
	}

	Log(LOG_DEBUG, "Header gives test type as '%s'\n", test_type);
	test_id = get_test_id(test_type);

	/* if the test is valid and has a save function, call it */
	if ( test_id != AMP_TEST_INVALID ) {
	    test = amp_tests[test_id];
	    if ( test != NULL ) {
		test->save_callback(monitor, p->timestamp, buffer, 
			body_target);
	    } else {
		Log(LOG_WARNING, "No save function for test '%s'\n", 
			test_type);
	    }
	} else {
	    Log(LOG_WARNING, "Unknown test type '%s'\n", test_type);
	}

	free(monitor);
	free(test_type);
	free(buffer);

	/* 
	 * The message doesn't get removed from the broker queue until we
	 * acknowledge it. By now we know that it should be saved ok.
	 */
	amqp_basic_ack(conn, getpid(), d->delivery_tag, 0);
    }

    return 0;
}
