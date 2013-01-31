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
 * Close the connection to the local broker. Should only be called when
 * measured is terminating.
 */
void close_broker_connection() {
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
}
