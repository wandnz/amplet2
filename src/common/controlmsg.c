#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <google/protobuf-c/protobuf-c.h>

#include "debug.h"
#include "controlmsg.h"
#include "controlmsg.pb-c.h"



/*
 * Write a control message to the control stream.
 */
static int do_control_write(BIO *ctrl, void *data, uint32_t datalen) {
    fd_set writefds;
    struct timeval timeout;
    int fd;
    int ready;
    int bytes;
    uint32_t total_written = 0;

    assert(ctrl);
    assert(data);

    BIO_get_fd(ctrl, &fd);

    do {
        /* make sure the underlying file descriptor is ready for writing */
        do {
            FD_ZERO(&writefds);
            FD_SET(fd, &writefds);

            timeout.tv_sec = CONTROL_CONNECTION_TIMEOUT;
            timeout.tv_usec = 0;

            ready = select(fd + 1, NULL, &writefds, NULL, &timeout);
        } while ( ready < 0 && errno == EINTR );

        if ( ready == 0 ) {
            Log(LOG_DEBUG, "Timeout writing control packet, aborting");
            return -1;
        }

        if ( ready < 0 ) {
            Log(LOG_WARNING, "Failed to write control packet: %s",
                    strerror(errno));
            return -1;
        }

        if ( FD_ISSET(fd, &writefds) ) {
            bytes = BIO_write(ctrl, (uint8_t*)data + total_written,
                    datalen - total_written);
            if ( bytes == 0 ) {
                Log(LOG_DEBUG, "Remote end closed control connection");
                return -1;
            }

            if ( bytes < 0 ) {
                if ( !BIO_should_retry(ctrl) ) {
                    Log(LOG_WARNING, "Error reading from BIO");
                    return -1;
                }
            } else {
                /* there was enough data, record how much we wrote */
                total_written += bytes;
            }
        }
    } while (total_written < datalen);

    return total_written;
}



/*
 * XXX set SSL_MODE_AUTO_RETRY when creating SSL socket? Will that mean
 * we never have to deal with reads while writing, or writes while reading?
 */
int write_control_packet(BIO *ctrl, void *data, uint32_t datalen) {
    uint32_t ctrllen = ntohl(datalen);

    /*
     * There is no delimiter for protocol buffers, so we need to send the
     * length of the message that will follow
     */
    if ( do_control_write(ctrl, &ctrllen, sizeof(ctrllen)) != sizeof(ctrllen) ){
        Log(LOG_WARNING, "Failed to write server control packet length");
        return -1;
    }

    /* Send the actual protocol buffer message onto the stream now */
    if ( do_control_write(ctrl, data, datalen) != datalen ) {
        Log(LOG_WARNING, "Failed to write server control packet data");
        return -1;
    }

    return datalen;
}



/*
 * Read a control message from the control stream.
 */
static int do_control_read(BIO *ctrl, void *data, int datalen) {
    fd_set readfds;
    struct timeval timeout;
    int fd;
    int ready;
    int bytes;
    int total_read = 0;

    assert(ctrl);
    assert(data);

    BIO_get_fd(ctrl, &fd);

    do {
        /* make sure the underlying file descriptor is ready for reading */
        do {
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);

            timeout.tv_sec = CONTROL_CONNECTION_TIMEOUT;
            timeout.tv_usec = 0;

            ready = select(fd + 1, &readfds, NULL, NULL, &timeout);
        } while ( ready < 0 && errno == EINTR );

        if ( ready == 0 ) {
            Log(LOG_DEBUG, "Timeout reading control packet, aborting");
            return -1;
        }

        if ( ready < 0 ) {
            Log(LOG_WARNING, "Failed to read control packet: %s",
                    strerror(errno));
            return -1;
        }

        if ( FD_ISSET(fd, &readfds) ) {
            bytes = BIO_read(ctrl, (uint8_t*)data + total_read,
                    datalen - total_read);
            if ( bytes == 0 ) {
                Log(LOG_DEBUG, "Remote end closed control connection");
                return 0;
            }

            /*
             * if we get an error, it might just be there isn't enough data
             * to decrypt the SSL response, we might need to wait for more
             */
            if ( bytes < 0 ) {
                if ( !BIO_should_retry(ctrl) ) {
                    Log(LOG_WARNING, "Error reading from BIO");
                    return -1;
                }
            } else {
                /* there was enough data, record how much we read */
                total_read += bytes;
            }
        }
    } while (total_read < datalen);

    return total_read;
}



/*
 * XXX set SSL_MODE_AUTO_RETRY when creating SSL socket?
 */
int read_control_packet(BIO *ctrl, void **data) {
    uint32_t datalen = 0;
    int result;

    /* read the 32 bit length field for this message */
    result = do_control_read(ctrl, &datalen, sizeof(datalen));

    if ( result != sizeof(datalen) ) {
        /* TODO do we want to return 0 and deal with it further up the chain? */
        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to read server control packet length");
        }
        return -1;
    }

    datalen = ntohl(datalen);

    /* make sure the message size is slightly sane before we allocate it */
    if ( datalen > MAX_CONTROL_MESSAGE_SIZE ) {
        Log(LOG_WARNING, "Ignoring too-large control message");
        return -1;
    }

    /* allocate storage for the following message */
    *data = calloc(1, datalen);

    /* read the message */
    result = do_control_read(ctrl, *data, datalen);

    if ( result != datalen ) {
        if ( result < 0 ) {
            Log(LOG_WARNING, "Failed to read server control packet data");
        }
        free(*data);
        return -1;
    }

    return datalen;
}



/*
 * Construct and send a HELLO message to the control stream.
 */
int send_control_hello(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options) {

    int len;
    void *buffer;
    int result;
    Amplet2__Controlmsg__Control msg = AMPLET2__CONTROLMSG__CONTROL__INIT;
    Amplet2__Controlmsg__Hello hello = AMPLET2__CONTROLMSG__HELLO__INIT;

    Log(LOG_DEBUG, "Sending HELLO");

    hello.has_options = 1;
    hello.options = *options;

    msg.hello = &hello;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__CONTROLMSG__CONTROL__TYPE__HELLO;

    len = amplet2__controlmsg__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__controlmsg__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    /*
     * We will take charge and free the options as well, the test shouldn't
     * require it any longer and it makes the calling function look ugly.
     */
    free(options->data);
    free(options);

    return result;
}



/*
 * Construct and send a READY message to the control stream.
 */
int send_control_ready(test_type_t test, BIO *ctrl,
        uint16_t port) {

    int len;
    void *buffer;
    int result;
    Amplet2__Controlmsg__Control msg = AMPLET2__CONTROLMSG__CONTROL__INIT;
    Amplet2__Controlmsg__Ready ready = AMPLET2__CONTROLMSG__READY__INIT;

    Log(LOG_DEBUG, "Sending READY with port %d", port);

    ready.has_test_port = 1;
    ready.test_port = port;
    msg.ready = &ready;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__CONTROLMSG__CONTROL__TYPE__READY;

    len = amplet2__controlmsg__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__controlmsg__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 * Construct and send a RECEIVE message to the control stream.
 */
int send_control_receive(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options){

    int len;
    void *buffer;
    int result;
    Amplet2__Controlmsg__Control msg = AMPLET2__CONTROLMSG__CONTROL__INIT;
    Amplet2__Controlmsg__Receive receive = AMPLET2__CONTROLMSG__RECEIVE__INIT;

    Log(LOG_DEBUG, "Sending RECEIVE");

    if ( options ) {
        receive.has_options = 1;
        receive.options = *options;
    }

    msg.receive = &receive;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__CONTROLMSG__CONTROL__TYPE__RECEIVE;

    len = amplet2__controlmsg__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__controlmsg__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 * Construct and send a SEND message to the control stream.
 */
int send_control_send(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *options) {

    int len;
    void *buffer;
    int result;
    Amplet2__Controlmsg__Control msg = AMPLET2__CONTROLMSG__CONTROL__INIT;
    Amplet2__Controlmsg__Send send = AMPLET2__CONTROLMSG__SEND__INIT;

    Log(LOG_DEBUG, "Sending SEND");

    //send.has_test_port = 1;
    //send.test_port = port;

    if ( options ) {
        send.has_options = 1;
        send.options = *options;
    }

    msg.send = &send;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__CONTROLMSG__CONTROL__TYPE__SEND;

    len = amplet2__controlmsg__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__controlmsg__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    /*
     * We will take charge and free the options as well, the test shouldn't
     * require it any longer and it makes the calling function look ugly.
     */
    if ( options ) {
        free(options->data);
        free(options);
    }

    return result;
}



/*
 * Construct and send a RESULT message to the control stream.
 */
int send_control_result(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *data) {

    int len;
    void *buffer;
    int result;
    Amplet2__Controlmsg__Control msg = AMPLET2__CONTROLMSG__CONTROL__INIT;
    Amplet2__Controlmsg__Result resmsg = AMPLET2__CONTROLMSG__RESULT__INIT;

    Log(LOG_DEBUG, "Sending RESULT");

    resmsg.result = *data;
    resmsg.has_result = 1;
    msg.result = &resmsg;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__CONTROLMSG__CONTROL__TYPE__RESULT;

    len = amplet2__controlmsg__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__controlmsg__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 * Construct and send a RENEW message to the control stream.
 */
int send_control_renew(test_type_t test, BIO *ctrl) {
    int len;
    void *buffer;
    int result;
    Amplet2__Controlmsg__Control msg = AMPLET2__CONTROLMSG__CONTROL__INIT;
    Amplet2__Controlmsg__Renew renew = AMPLET2__CONTROLMSG__RENEW__INIT;

    Log(LOG_DEBUG, "Sending RENEW message");

    msg.renew = &renew;
    msg.has_test = 1;
    msg.test = test;
    msg.has_type = 1;
    msg.type = AMPLET2__CONTROLMSG__CONTROL__TYPE__RENEW;

    len = amplet2__controlmsg__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__controlmsg__control__pack(&msg, buffer);

    result = write_control_packet(ctrl, buffer, len);

    free(buffer);

    return result;
}



/*
 * Parse a HELLO message using the test specific parsing function, and update
 * the options structure using the values from the message.
 */
static int parse_control_hello(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {

    Amplet2__Controlmsg__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__controlmsg__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__CONTROLMSG__CONTROL__TYPE__HELLO ) {
        Log(LOG_WARNING, "Not a HELLO packet, aborting");
        if ( msg ) {
            amplet2__controlmsg__control__free_unpacked(msg, NULL);
        }
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "HELLO is for wrong test type, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->hello || (parse_func && !msg->hello->has_options) ) {
        Log(LOG_WARNING, "Malformed HELLO packet, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    /* call the test specific function to get the test options */
    if ( parse_func && options ) {
        *options = parse_func(&msg->hello->options);
    } else if ( options ) {
        *options = NULL;
    }

    amplet2__controlmsg__control__free_unpacked(msg, NULL);
    return 0;
}



/*
 * Parse a READY message and update the port number using the value from the
 * message.
 */
static int parse_control_ready(test_type_t test, void *data, uint32_t len,
        uint16_t *port) {

    Amplet2__Controlmsg__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__controlmsg__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__CONTROLMSG__CONTROL__TYPE__READY ) {
        Log(LOG_WARNING, "Not a READY packet, aborting");
        if ( msg ) {
            amplet2__controlmsg__control__free_unpacked(msg, NULL);
        }
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "READY is for wrong test type, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->ready || !msg->ready->has_test_port ) {
        Log(LOG_WARNING, "Malformed READY packet, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    *port = msg->ready->test_port;

    amplet2__controlmsg__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 * Parse a RECEIVE message using the test specific parsing function, and update
 * the options structure using the values from the message.
 */
int parse_control_receive(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {

    Amplet2__Controlmsg__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__controlmsg__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__CONTROLMSG__CONTROL__TYPE__RECEIVE ) {
        Log(LOG_WARNING, "Not a RECEIVE packet, aborting");
        if ( msg ) {
            amplet2__controlmsg__control__free_unpacked(msg, NULL);
        }
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "RECEIVE is for wrong test type, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->receive || (parse_func && !msg->receive->has_options) ) {
        Log(LOG_WARNING, "Malformed RECEIVE packet, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( parse_func && options ) {
        *options = parse_func(&msg->receive->options);
    } else if ( options ) {
        *options = NULL;
    }

    amplet2__controlmsg__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 * Parse a SEND message using the test specific parsing function, and update
 * the options structure using the values from the message.
 */
int parse_control_send(test_type_t test, void *data, uint32_t len,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {

    Amplet2__Controlmsg__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__controlmsg__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__CONTROLMSG__CONTROL__TYPE__SEND ) {
        Log(LOG_WARNING, "Not a SEND packet, aborting");
        if ( msg ) {
            amplet2__controlmsg__control__free_unpacked(msg, NULL);
        }
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "SEND is for wrong test type, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->send || (parse_func && !msg->send->has_options) ) {
        Log(LOG_WARNING, "Malformed SEND packet, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( parse_func && options ) {
        *options = parse_func(&msg->send->options);
    } else if ( options ) {
        *options = NULL;
    }

    amplet2__controlmsg__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 * Parse a RESULT message and extract the result buffer.
 */
static int parse_control_result(test_type_t test, void *data, uint32_t len,
        ProtobufCBinaryData *results ) {
    Amplet2__Controlmsg__Control *msg;

    assert(data);

    /* unpack all the data */
    msg = amplet2__controlmsg__control__unpack(NULL, len, data);

    if ( !msg || !msg->has_type ||
            msg->type != AMPLET2__CONTROLMSG__CONTROL__TYPE__RESULT ) {
        Log(LOG_WARNING, "Not a RESULT packet, aborting");
        if ( msg ) {
            amplet2__controlmsg__control__free_unpacked(msg, NULL);
        }
        return -1;
    }

    if ( !msg->has_test || msg->test != test ) {
        Log(LOG_WARNING, "RESULT is for wrong test type, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    if ( !msg->result || !msg->result->has_result/*|| !msg->result->result*/ ) {
        Log(LOG_WARNING, "Malformed RESULT packet, aborting");
        amplet2__controlmsg__control__free_unpacked(msg, NULL);
        return -1;
    }

    results->len = msg->result->result.len;
    results->data = malloc(results->len);
    memcpy(results->data, msg->result->result.data, msg->result->result.len);

    amplet2__controlmsg__control__free_unpacked(msg, NULL);

    return 0;
}



/*
 * Read and parse a HELLO message, updating the options structure using the
 * values from the message.
 */
int read_control_hello(test_type_t test, BIO *ctrl,
        void **options, void *(*parse_func)(ProtobufCBinaryData *data)) {
    void *data;
    int len;

    /* read the packet from the stream */
    if ( (len = read_control_packet(ctrl, &data)) < 0 ) {
        Log(LOG_WARNING, "Failed to read HELLO packet");
        return -1;
    }

    /* validate it as a HELLO packet and then try to extract options */
    if ( parse_control_hello(test, data, len, options, parse_func) < 0 ) {
        Log(LOG_WARNING, "Failed to parse HELLO packet");
        free(data);
        return -1;
    }

    free(data);

    return 0;
}



/*
 * Read and parse a READY message, updating the port number using the value
 * from the message.
 */
int read_control_ready(test_type_t test, BIO *ctrl,
        uint16_t *port) {

    void *data;
    int len;

    if ( (len = read_control_packet(ctrl, &data)) < 0 ) {
        Log(LOG_ERR, "Failed to read READY packet");
        return -1;
    }

    if ( parse_control_ready(test, data, len, port) < 0 ) {
        Log(LOG_WARNING, "Failed to parse READY packet");
        free(data);
        return -1;
    }

    free(data);

    return 0;
}



/*
 * Read and parse a RESULT message, extracting the result buffer for the test
 * to further process, print, report etc.
 */
int read_control_result(test_type_t test, BIO *ctrl,
        ProtobufCBinaryData *results) {

    void *data;
    int len;

    Log(LOG_DEBUG, "Waiting for RESULT packet");

    if ( (len = read_control_packet(ctrl, &data)) < 0 ) {
        Log(LOG_ERR, "Failed to read READY packet");
        return -1;
    }

    if ( parse_control_result(test, data, len, results) < 0 ) {
        Log(LOG_WARNING, "Failed to parse RESULT packet");
        free(data);
        return -1;
    }

    free(data);

    return 0;
}
