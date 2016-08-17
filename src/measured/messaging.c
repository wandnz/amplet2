#include <stdlib.h>
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
 * Create a connection to the broker (local or remote) that measured can use
 * to report data from tests. Each test *should* use a different channel within
 * this connection but they currently all create their own individual
 * connections as sharing connections/channels becomes tricky when multiple
 * processes are involved.
 * TODO create a connection that persists for the lifetime of the main process
 * that allocates channels within it for each test process.
 */
static int connect_to_broker(void) {
    amqp_socket_t *sock;
    char *collector = vars.vialocal ? vars.local : vars.collector;
    int port = vars.vialocal ? AMQP_PORT : vars.port;
    char *vhost = vars.vialocal ? vars.ampname : vars.vhost;

    Log(LOG_DEBUG, "Opening new connection to broker %s:%d\n", collector, port);

    conn = amqp_new_connection();

    if ( !vars.vialocal && vars.ssl ) {

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

        /* on by default, but set it in case later versions change defaults */
        amqp_ssl_socket_set_verify(sock, 1);

        if ( amqp_socket_open(sock, collector, port) != 0 ) {
            Log(LOG_ERR, "Failed to open connection to %s:%d", collector, port);
            return -1;
        }

        Log(LOG_DEBUG, "Logging in to vhost '%s' with EXTERNAL auth", vhost);

        /* login using EXTERNAL, still need to specify user name though */
        if ( (amqp_login(conn, vhost, 0, AMQP_FRAME_MAX, 0,
                        AMQP_SASL_METHOD_EXTERNAL, vars.ampname)
             ).reply_type != AMQP_RESPONSE_NORMAL ) {
            Log(LOG_ERR, "Failed to login to broker");
            return -1;
        }

    } else {

        if ( (sock = amqp_tcp_socket_new(conn)) == NULL ) {
            Log(LOG_ERR, "Failed to create TCP socket\n");
            return -1;
        }

        if ( amqp_socket_open(sock, collector, port) != 0 ) {
            Log(LOG_ERR, "Failed to open connection to %s:%d", collector, port);
            return -1;
        }

        Log(LOG_DEBUG, "Logging in to vhost '%s' as '%s' with PLAIN auth",
                vhost, vars.ampname);

        /* login using PLAIN, must specify username and password */
        if ( (amqp_login(conn, vhost, 0, AMQP_FRAME_MAX,0,
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
static void close_broker_connection(void) {
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
}



/*
 * Report results for a single test to the broker.
 *
 * example amqp_table_t stuff:
 * https://groups.google.com/forum/?fromgroups=#!topic/rabbitmq-discuss/M_8I12gWxbQ
 * rabbitmq-c/tests/test_tables.c
 */
int report_to_broker(test_type_t type, amp_test_result_t *result) {

    amqp_basic_properties_t props;
    amqp_bytes_t data;
    amqp_table_t headers;
    amqp_table_entry_t table_entries;
    char *exchange = vars.vialocal ? AMQP_LOCAL_EXCHANGE : vars.exchange;
    char *routingkey = vars.vialocal ? AMQP_LOCAL_ROUTING_KEY : vars.routingkey;

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

    /* The name of the test data is being reported for */
    table_entries.key = amqp_cstring_bytes("x-amp-test-type");
    table_entries.value.kind = AMQP_FIELD_KIND_UTF8;
    table_entries.value.value.bytes = amqp_cstring_bytes(amp_tests[type]->name);

    /* Add all the individual headers to the header table - only test type */
    headers.num_entries = 1;
    headers.entries = &table_entries;

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
    props.timestamp = result->timestamp;
    /*
     * If the userid is set, it must match the authenticated username or the
     * message will be rejected by the rabbitmq broker. If it is not set then
     * the message will be rejected by the NNTSC dataparser
     */
    props.user_id = amqp_cstring_bytes(vars.ampname);

    /* Add the binary blob, the other end will know how to unpack it */
    data.len = result->len;
    data.bytes = result->data;

    /* publish the message */
    Log(LOG_DEBUG, "Publishing message to exchange '%s', routingkey '%s'\n",
            exchange, routingkey);

    if ( amqp_basic_publish(conn,
	    getpid(),				    /* channel, our pid */
	    amqp_cstring_bytes(exchange),           /* exchange name */
	    amqp_cstring_bytes(routingkey),         /* routing key */
	    0,					    /* mandatory */
	    0,					    /* immediate */
	    &props,				    /* properties */
	    data) < 0 ) {			    /* body */

	Log(LOG_ERR, "Failed to publish message");
	amqp_channel_close(conn, getpid(), AMQP_REPLY_SUCCESS);
	close_broker_connection();
	return -1;
    }

    Log(LOG_DEBUG, "Closing channel %d\n", getpid());
    amqp_channel_close(conn, getpid(), AMQP_REPLY_SUCCESS);

    close_broker_connection();
    return 0;
}
