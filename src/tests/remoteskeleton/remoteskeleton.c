/*
 * Skeleton test to demonstrate how to write a test for amplet2.
 */
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <openssl/bio.h>

#include "tests.h"
#include "debug.h"
#include "testlib.h"
#include "serverlib.h"
#include "remoteskeleton.pb-c.h"
#include "../../measured/control.h"

amp_test_result_t* run_remoteskeleton(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_remoteskeleton(amp_test_result_t *result);
void server_remoteskeleton(int argc, char *argv[], BIO *ctrl);
test_t *register_test(void);



static void usage(char *prog) {
    fprintf(stderr, "%s test has no required arguments.\n", prog);
    fprintf(stderr, "Any arguments it receives it will simply print.\n");
}



/*
 * Build the protocol buffer message containing the result.
 */
static amp_test_result_t* report_result(struct timeval *start_time,
        uint32_t valid) {

    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Log(LOG_DEBUG, "Building remoteskeleton report, valid:%d\n", valid);

    Amplet2__Remoteskeleton__Report msg = AMPLET2__REMOTESKELETON__REPORT__INIT;
    Amplet2__Remoteskeleton__Header header =
        AMPLET2__REMOTESKELETON__HEADER__INIT;

    header.has_valid = 1;
    header.valid = valid;

    msg.header = &header;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__remoteskeleton__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__remoteskeleton__report__pack(&msg, result->data);

    return result;
}



/*
 * Very simple main function to show how tests can be run.
 */
amp_test_result_t* run_remoteskeleton(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int i;
    char address[INET6_ADDRSTRLEN];
    struct timeval start_time;
    uint32_t valid;
    int opt;
    struct sockopt_t sockopts;
    amp_test_result_t *result;
    BIO *ctrl;
    Amplet2__Measured__Response response;

    printf("remote skeleton test\n");

    memset(&sockopts, 0, sizeof(sockopts));

    /* use getopt to check for -h first, then fall through to dump all args */
    while ( (opt = getopt(argc, argv, "hI:4:6:")) != -1 ) {
	switch ( opt ) {
	    case 'h': usage(argv[0]); exit(0);
            case 'I': sockopts.device = optarg; break;
            case '4': sockopts.sourcev4 = get_numeric_address(optarg, NULL);
                      break;
            case '6': sockopts.sourcev6 = get_numeric_address(optarg, NULL);
                      break;
            default: /* pass through */ break;
	};
    }

    if ( count < 1 ) {
        Log(LOG_WARNING, "No destination specified for remote skeleton test");
        return NULL;
    }

    if ( gettimeofday(&start_time, NULL) != 0 ) {
	Log(LOG_ERR, "Could not gettimeofday(), aborting test");
	exit(-1);
    }

    /* print all the arguments that were passed in */
    printf("args:\n");
    for ( i=0; i<argc; i++) {
	printf("\targv[%d]: %s\n", i, argv[i]);
    }

    /* print all the destinations that were passed in */
    printf("dests: %d\n", count);
    valid = count;
    for ( i = 0; i < count; i++ ) {
	if ( dests[i]->ai_family == AF_INET ) {
	    inet_ntop(AF_INET,
		    &((struct sockaddr_in*)dests[i]->ai_addr)->sin_addr,
		    address, INET6_ADDRSTRLEN);
	} else if ( dests[i]->ai_family == AF_INET6 ) {
	    inet_ntop(AF_INET6,
		    &((struct sockaddr_in6*)dests[i]->ai_addr)->sin6_addr,
		    address, INET6_ADDRSTRLEN);
	} else {
            valid--;
	    continue;
	}
	printf("\t%s\n", address);
    }

    /* Connect to the control server to start/configure the test. Just use the
     * first destination for this, most tests involving servers will only
     * connect to a single target.
     */
    if ( (ctrl=connect_control_server(dests[0],
                    atoi(DEFAULT_AMPLET_CONTROL_PORT), &sockopts)) == NULL ) {
	Log(LOG_WARNING, "Failed to connect control server");
	return NULL;
    }

    if ( start_remote_server(ctrl, AMP_TEST_REMOTE_SKELETON) < 0 ) {
        Log(LOG_WARNING, "Failed to start remote server");
        return NULL;
    }

    /* make sure the server was started properly */
    if ( read_measured_response(ctrl, &response) < 0 ) {
        Log(LOG_WARNING, "Failed to read server control response");
        return NULL;
    }

    /* TODO return something useful if this was remotely triggered? */
    if ( response.code != MEASURED_CONTROL_OK ) {
        Log(LOG_WARNING, "Failed to start server: %d %s", response.code,
                response.message);
        return NULL;
    }

    /* do something useful with the test server here */

    close_control_connection(ctrl);

    /* report some sort of dummy result */
    result = report_result(&start_time, valid);

    return result;
}



/*
 * Unpack the protocol buffer object and print the results of the skeleton test.
 */
void print_remoteskeleton(amp_test_result_t *result) {
    Amplet2__Remoteskeleton__Report *msg;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__remoteskeleton__report__unpack(NULL, result->len,
            result->data);

    assert(msg);
    assert(msg->header);

    printf("Result: got %d address(es) of known family (IPv4/IPv6)\n",
            msg->header->valid);

    amplet2__remoteskeleton__report__free_unpacked(msg, NULL);
}



/*
 * Function run by the server, you probably want to listen for connections
 * from the client to do whatever testing you need.
 */
void server_remoteskeleton(__attribute__((unused))int argc,
        __attribute__((unused))char *argv[],
        __attribute__((unused))BIO *bio) {

    printf("SKELETON SERVER\n");
}


/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_REMOTE_SKELETON;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("remoteskeleton");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 1;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 30;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_remoteskeleton;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_remoteskeleton;

    /* function to run on the remote end to assist with the test */
    new_test->server_callback = server_remoteskeleton;

    /* don't give the skeleton test a SIGINT warning */
    new_test->sigint = 0;

    return new_test;
}
