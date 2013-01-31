#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <amqp.h>
#include <amqp_framing.h>

#include "testlib.h"
#include "debug.h"



/*
 * Given a pair of sockets (ipv4 and ipv6), wait for data to arrive on either
 * of them, up to maxwait microseconds. If data arrives before the timeout
 * then return which socket received the data, otherwise -1.
 */
static int wait_for_data(struct socket_t *sockets, int *maxwait) {
    struct timeval start_time, end_time;
    struct timeval timeout;
    int delay;
    int max_fd;
    int ready;
    fd_set readset;

    assert(sockets);
    assert(sockets->socket || sockets->socket6);

    gettimeofday(&start_time, NULL);

    max_fd = -1;
    delay = 0;

    do {
	/* 
	 * if there has been an error then update timeout by how long we have
	 * already taken so we can carry on where we left off
	 */
	if ( delay > *maxwait ) {
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 0;
	} else {
	    timeout.tv_sec = S_FROM_US(*maxwait - delay);
	    timeout.tv_usec = US_FROM_US(*maxwait - delay);
	}

	/* fd sets are undefined after an error, so set them every time too */
	FD_ZERO(&readset);
	if ( sockets->socket > 0 ) {
	    FD_SET(sockets->socket, &readset);
	    max_fd = sockets->socket;
	}

	if ( sockets->socket6 > 0 ) {
	    FD_SET(sockets->socket6, &readset);
	    if ( sockets->socket6 > max_fd ) {
		max_fd = sockets->socket6;
	    }
	}

	ready = select(max_fd+1, &readset, NULL, NULL, &timeout);

	/* 
	 * we can't always trust the value of timeout after select returns, so
	 * check for ourselves how much time has elapsed
	 */
	gettimeofday(&end_time, NULL);
	delay = DIFF_TV_US(end_time, start_time);

	/* if delay is less than zero then maybe the clock was adjusted on us */
	if ( delay < 0 ) {
	    delay = 0;
	}

	/* continue until there is data to read or we get a non EINTR error */
    } while ( ready < 0 && errno == EINTR );

    /* remove the time waited so far from maxwait */
    *maxwait -= delay;
    if ( *maxwait < 0 ) {
	*maxwait = 0;
    }

    /* if there was a non-EINTR error then report it */
    if ( ready < 0 ) {
	Log(LOG_WARNING, "select() failed");
	return -1;
    }

    /* return the appropriate socket that has data waiting */
    if ( sockets->socket > 0 && FD_ISSET(sockets->socket, &readset) ) {
	return AF_INET;
    }

    if ( sockets->socket6 > 0 && FD_ISSET(sockets->socket6, &readset) ) {
	return AF_INET6;
    }

    return -1;
}



/*
 * Wait for up to timeout microseconds to receive a packet on the given 
 * sockets and return the number of bytes read.
 */
int get_packet(struct socket_t *sockets, char *buf, int len,
        struct sockaddr *saddr, int *timeout) {

    int bytes;
    int sock;
    int family;
    socklen_t addrlen;
    
    assert(sockets);
    assert(sockets->socket || sockets->socket6);

    /* wait for data to be ready to read, up to timeout (wait will update it) */
    if ( (family = wait_for_data(sockets, timeout)) <= 0 ) {
        return 0;
    }

    /* determine which socket we have received data on and read from it */
    switch ( family ) {
        case AF_INET: sock = sockets->socket;
                      addrlen = sizeof(struct sockaddr_in);
                      break;
        case AF_INET6: sock = sockets->socket6;
                       addrlen = sizeof(struct sockaddr_in6);
                       break;
        default: return 0;
    };

    if ( (bytes = recvfrom(sock, buf, len, 0, saddr, &addrlen)) < 0 ) {
        Log(LOG_ERR, "Failed to recvfrom()");
        exit(-1);
    }

    return bytes;
}



/*
 * Enforce a minimum inter-packet delay for test traffic. Try to send a packet
 * but if it is too soon for the test to be sending again then return a delay
 * time to wait (in microseconds).
 */
int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest) {

    int bytes_sent;
    static struct timeval last = {0, 0};
    struct timeval now;
    int delay;

    assert(sock > 0);
    assert(size > 0);
    assert(packet);
    assert(dest);

    gettimeofday(&now, NULL);

    /* determine how much time is left to wait until the minimum delay */
    if ( last.tv_sec != 0 && DIFF_TV_US(now, last) < MIN_INTER_PACKET_DELAY ) {
	delay = MIN_INTER_PACKET_DELAY - DIFF_TV_US(now, last);
    } else {
	delay = 0;
	last.tv_sec = now.tv_sec;
	last.tv_usec = now.tv_usec;
    }

    /* 
     * if there is still time to wait before the next packet then return
     * control to the caller, in case they want to do more work while waiting
     */
    if ( delay != 0 ) {
	return delay;
    }

    bytes_sent = sendto(sock, packet, size, 0, dest->ai_addr, dest->ai_addrlen);

    /* TODO determine error and/or send any unsent bytes */
    if ( bytes_sent != size ) {
	Log(LOG_ERR, "Only sent %d of %d bytes", bytes_sent, size);
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
    extern amqp_connection_state_t conn;

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
