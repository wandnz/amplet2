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
    amqp_basic_consume(conn, getpid(), queuename, amqp_empty_bytes, 0, 1, 0, 
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
    char *type = NULL;
    char *buffer = NULL;

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
	printf("Delivery %u, exchange %.*s routingkey %.*s\n",
		(unsigned) d->delivery_tag,
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
	/*
	if (p->_flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
	    printf("Content-type: %.*s\n",
		    (int) p->content_type.len, (char *) p->content_type.bytes);
	}
	*/

	/* XXX DEBUG */
	if (p->_flags & AMQP_BASIC_HEADERS_FLAG) {
	    int i;
	    amqp_table_t headers = p->headers;
	    for ( i=0; i<headers.num_entries; i++ ) {
		printf("%.*s: ", (int)headers.entries[i].key.len,
			(char *)headers.entries[i].key.bytes);

		if ( headers.entries[i].value.kind == AMQP_FIELD_KIND_UTF8 ) {
		    printf("%.*s\n", (int)headers.entries[i].value.value.bytes.len,
			    (char *)headers.entries[i].value.value.bytes.bytes);
		} else if ( headers.entries[i].value.kind == AMQP_FIELD_KIND_TIMESTAMP ) {
		    printf("%"PRIu64"\n", headers.entries[i].value.value.u64);
		} else {
		    printf("unknown type\n");
		}
	    }
	}

	/* TODO actual check for valid headers */
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
		    type = strndup((char *)
			    headers.entries[i].value.value.bytes.bytes, 
			    (int)headers.entries[i].value.value.bytes.len);
		}
	    }
	}

    

	/* XXX DEBUG */
	if (p->_flags & AMQP_BASIC_TIMESTAMP_FLAG) {
	    printf("timestamp: %"PRIu64"\n", p->timestamp);
	}

	/* TODO actual check - what to do if no timestamp? */
	if ( (p->_flags & AMQP_BASIC_TIMESTAMP_FLAG) == 0 ) {
	    printf("not a valid data packet, missing timestamp\n");
	    break;
	}
	printf("----\n");

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
	    /*
	       amqp_dump(frame.payload.body_fragment.bytes,
	       frame.payload.body_fragment.len);
	     */
	}

	if (body_received != body_target) {
	    /* Can only happen when amqp_simple_wait_frame returns <= 0 */
	    /* We break here to close the connection */
	    free(buffer);
	    break;
	}

	/* TODO call the appropriate test save function */
	{
	    test_t *test = amp_tests[AMP_TEST_ICMP];
	    fprintf(stderr, "need to look up test: %s\n", type);
	    test->save_callback(monitor, p->timestamp, buffer, body_target);
	}
	free(monitor);
	free(type);
	free(buffer);

	/* TODO messages were being removed from queue even withou acks? */
	//amqp_basic_ack(conn, getpid(), d->delivery_tag, 0);
    }

    return 0;
}
