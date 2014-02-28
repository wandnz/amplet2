#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#include <amqp_ssl_socket.h>
#include <amqp_tcp_socket.h>

#include "messaging.h"
#include "debug.h"
#include "modules.h"
#include "global.h"


/*
 * Create a connection to the local broker that measured can use to report
 * data for all tests. Each test will use a different channel within this
 * connection (sharing channels leads to broken behaviour). This will persist
 * for the lifetime of measured.
 * TODO can we detect this going away and reconnect if it does so?
 */
int connect_to_broker() {
    amqp_socket_t *sock;

    /* this connection will be held open forever while measured runs */
    Log(LOG_DEBUG, "Opening new connection to broker on %s:%d\n",
	    vars.collector, vars.port);

    conn = amqp_new_connection();

    if ( vars.ssl ) {

        if ( (sock = amqp_ssl_socket_new(conn)) == NULL ) {
            Log(LOG_ERR, "Failed to create SSL socket\n");
            return -1;
        }

        if ( amqp_ssl_socket_set_cacert(sock, vars.amqp_ssl.cacert) != 0 ) {
            Log(LOG_ERR, "Failed to set CA certificate\n");
            return -1;
        }

        if ( amqp_ssl_socket_set_key(sock, vars.amqp_ssl.cert,
                    vars.amqp_ssl.key) != 0 ) {
            Log(LOG_ERR, "Failed to set client certificate\n");
            return -1;
        }

        if ( amqp_socket_open(sock, vars.collector, vars.port) != 0 ) {
            Log(LOG_ERR, "Failed to open connection to %s:%d",
                    vars.collector, vars.port);
            return -1;
        }

        /* login using EXTERNAL, no need to specify user name */
        if ( (amqp_login(conn, "/", 0, AMQP_FRAME_MAX, 0,
                        AMQP_SASL_METHOD_EXTERNAL)
             ).reply_type != AMQP_RESPONSE_NORMAL ) {
            Log(LOG_ERR, "Failed to login to broker");
            return -1;
        }

    } else {

        if ( (sock = amqp_tcp_socket_new(conn)) == NULL ) {
            Log(LOG_ERR, "Failed to create TCP socket\n");
            return -1;
        }

        if ( amqp_socket_open(sock, vars.collector, vars.port) != 0 ) {
            Log(LOG_ERR, "Failed to open connection to %s:%d",
                    vars.collector, vars.port);
            return -1;
        }

        /* login using PLAIN, must specify username and password */
        /* TODO make credentials configurable, or remove this entirely? */
        if ( (amqp_login(conn, "/", 0, AMQP_FRAME_MAX,0,
                        AMQP_SASL_METHOD_PLAIN, vars.ampname, vars.ampname)
             ).reply_type != AMQP_RESPONSE_NORMAL ) {
            Log(LOG_ERR, "Failed to login to broker");
            return -1;
        }
    }

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



/*
 * XXX is this file the right place for this function? only used by measured
 * Report results for a single test to the local broker.
 *
 * example amqp_table_t stuff:
 * https://groups.google.com/forum/?fromgroups=#!topic/rabbitmq-discuss/M_8I12gWxbQ
 * root@machine4:~/rabbitmq/rabbitmq-c/tests/test_tables.c
 */
int report_to_broker(test_type_t type, uint64_t timestamp, void *bytes,
	size_t len) {

    amqp_basic_properties_t props;
    amqp_bytes_t data;
    amqp_table_t headers;
    amqp_table_entry_t table_entries[2];

    /* check the test id is valid */
    if ( type >= AMP_TEST_LAST || type <= AMP_TEST_INVALID ) {
	Log(LOG_WARNING, "Invalid test type %d, not reporting\n", type);
	return -1;
    }

    /*
     * Ideally this would only happen once and the same connection would be
     * reused for all tests, but with their own channel. A connection can't
     * be shared by multiple processes/threads however, so they can't just
     * create themselves a new channel using the single connection object -
     * they need to make their own connection, or the master parent process
     * needs to create the channel and somehow tell the child which channel
     * to use.
     * TODO how to make this work with a single connection, multiple channels.
     */
    if ( connect_to_broker() < 0 ) {
	return -1;
    }

    /*
     * open a new channel for every reporting process, there may be multiple
     * of these going on at once so they need individual channels
     */
    Log(LOG_DEBUG, "Opening new channel %d to broker\n", getpid());
    amqp_channel_open(conn, getpid());

    if ( (amqp_get_rpc_reply(conn).reply_type) != AMQP_RESPONSE_NORMAL ) {
	Log(LOG_ERR, "Failed to open channel");
	close_broker_connection();
	return -1;
    }

    /*
     * Add all the headers to describe the data we are sending:
     *	- source monitor
     *	- test type
     *	- timestamp? already a property, but i need to set
     */

    /* XXX deprecated, remove, the name is now done with validated user_id */
    /* The name of the reporting monitor (our local ampname) */
    table_entries[0].key = amqp_cstring_bytes("x-amp-source-monitor");
    table_entries[0].value.kind = AMQP_FIELD_KIND_UTF8;
    table_entries[0].value.value.bytes = amqp_cstring_bytes(vars.ampname);

    /* The name of the test data is being reported for */
    table_entries[1].key = amqp_cstring_bytes("x-amp-test-type");
    table_entries[1].value.kind = AMQP_FIELD_KIND_UTF8;
    table_entries[1].value.value.bytes =
	amqp_cstring_bytes(amp_tests[type]->name);

    /* Add all the individual headers to the header table */
    headers.num_entries = 2;
    headers.entries = table_entries;

    /* Mark the flags that will be present */
    props._flags =
	AMQP_BASIC_CONTENT_TYPE_FLAG |
	AMQP_BASIC_DELIVERY_MODE_FLAG |
	AMQP_BASIC_HEADERS_FLAG |
	AMQP_BASIC_TIMESTAMP_FLAG |
        AMQP_BASIC_USER_ID_FLAG;

    props.content_type = amqp_cstring_bytes("application/octet-stream");
    props.delivery_mode = 2; /* persistent delivery mode */
    props.headers = headers;
    props.timestamp = timestamp;
    /*
     * If the userid is set, it must match the authenticated username or the
     * message will be rejected by the rabbitmq broker. If it is not set then
     * the message will be rejected by the NNTSC dataparser
     */
    props.user_id = amqp_cstring_bytes(vars.ampname);

    /* jump dump a binary blob similar to old style? */
    data.len = len;
    data.bytes = bytes;

    /* publish the message */
    Log(LOG_DEBUG, "Publishing message\n");
    if ( amqp_basic_publish(conn,
	    getpid(),				    /* channel, our pid */
	    amqp_cstring_bytes(vars.exchange),	    /* exchange name */
	    amqp_cstring_bytes(vars.routingkey),    /* routing key */
	    0,					    /* mandatory */
	    0,					    /* immediate */
	    &props,				    /* properties */
	    data) < 0 ) {			    /* body */

	Log(LOG_ERR, "Failed to publish message");
	//XXX should this use success value here?
	amqp_channel_close(conn, getpid(), AMQP_REPLY_SUCCESS);
	close_broker_connection();
	return -1;
    }

    /* TODO do something if publishing fails? */
    Log(LOG_DEBUG, "Closing channel %d\n", getpid());
    amqp_channel_close(conn, getpid(), AMQP_REPLY_SUCCESS);

    close_broker_connection();
    return 0;
}
