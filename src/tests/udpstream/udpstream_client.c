#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "udpstream.h"
#include "serverlib.h" //XXX this needs a better name




/*
 * TODO could this be a library function too, with a function pointer?
 */
static int run_test(struct addrinfo *server, struct opt_t *options,
        struct temp_sockopt_t_xxx *socket_options) {
    uint16_t test_port;//XXX int? needs values less than zero
    int control_socket, test_socket;
    //struct temp_sockopt_t_xxx optxxx;
    struct sockaddr_storage ss;
    socklen_t socklen = sizeof(ss);

    printf("run test\n");
    socket_options->cport = options->cport;//XXX
    socket_options->tport = options->tport;//XXX
    socket_options->socktype = SOCK_STREAM;
    socket_options->protocol = IPPROTO_TCP;

    /* connect to the control socket on the server */
    control_socket = connect_to_server(server, socket_options,
            options->cport);//XXX socket_options?
    printf("control = %d\n", control_socket);

    /* send hello */
    if ( send_control_hello(control_socket, socket_options) < 0 ) {
        Log(LOG_WARNING, "Failed to send HELLO packet, aborting");
        close(control_socket);
        return -1;
    }

    /* all good so far, create our test socket so it is ready early on */
    if ( (test_socket=socket(server->ai_family, SOCK_DGRAM, IPPROTO_UDP)) < 0 ){
        Log(LOG_WARNING, "Failed to create control socket:%s", strerror(errno));
        close(control_socket);
        return -1;
    }

    /* read port */
    // XXX test_port or options->tport?
    /*
    if ( (test_port = read_control_ready(control_socket)) < 0 ) {
        Log(LOG_WARNING, "Failed to send READY packet, aborting");
        close(control_socket);
        return -1;
    }

    //XXX
    printf("test port = %d\n", test_port);
    ((struct sockaddr_in *)server->ai_addr)->sin_port = ntohs(test_port);
*/


    /* connect the test socket */
#if 0
    /* XXX don't connect the udp sockets, we want to create it sooner */
    optxxx.socktype = SOCK_DGRAM;
    optxxx.protocol = IPPROTO_UDP;
    test_socket = connect_to_server(server, &optxxx, test_port);
#endif

    /* run the test schedule */
    // TODO switch based on schedule

    /* TODO instruct server to send otherwise send data */
    send_control_receive(control_socket, options->packet_count);

    if ( (test_port = read_control_ready(control_socket)) < 0 ) {
        Log(LOG_WARNING, "Failed to send READY packet, aborting");
        close(control_socket);
        return -1;
    }

    //XXX
    printf("test port = %d\n", test_port);
    ((struct sockaddr_in *)server->ai_addr)->sin_port = ntohs(test_port);

    send_udp_stream(test_socket, server, options);


    getsockname(test_socket, (struct sockaddr *)&ss, &socklen);
    //send_control_send(control_socket/*, sockopts->tport*/);
    send_control_ready(control_socket, ntohs(((struct sockaddr_in *)&ss)->sin_port));

    /* wait for the data stream from the server */
    receive_udp_stream(test_socket);

    /* report results */

    return 0;
}



/*
 *
 */
int run_udpstream_client(int argc, char *argv[], int count,
        struct addrinfo **dests) {

    int opt;
    struct opt_t test_options;
    struct temp_sockopt_t_xxx socket_options;
    struct timeval start_time;
    struct info_t *info;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    char *client;
    amp_test_meta_t meta;
    extern struct option long_options[];

    Log(LOG_DEBUG, "Starting udpstream test");

    /* set some sensible defaults */
    //XXX set better inter packet delay, using MIN as a floor?
    //test_options.inter_packet_delay = MIN_INTER_PACKET_DELAY;
    test_options.packet_spacing = MIN_INTER_PACKET_DELAY;
    test_options.packet_size = DEFAULT_UDPSTREAM_PACKET_LENGTH;
    test_options.packet_count = DEFAULT_UDPSTREAM_PACKET_COUNT;
    test_options.cport = DEFAULT_CONTROL_PORT;
    test_options.tport = DEFAULT_TEST_PORT;
    test_options.perturbate = 0;
    socket_options.sourcev4 = NULL;
    socket_options.sourcev6 = NULL;
    socket_options.device = NULL;
    client = NULL;

    /* TODO udp port */
    while ( (opt = getopt_long(argc, argv, "hvI:Z:p:rs:c:n:4:6:",
                    long_options, NULL)) != -1 ) {
	switch ( opt ) {
            case '4':
                socket_options.sourcev4 = get_numeric_address(optarg, NULL);
                break;
            case '6':
                socket_options.sourcev6 = get_numeric_address(optarg, NULL);
                break;
            case 'I': socket_options.device = optarg; break;
            case 'c': client = optarg; break;
            case 'Z': test_options.packet_spacing = atoi(optarg); break;
	    case 'p': test_options.perturbate = atoi(optarg); break;
	    case 's': test_options.packet_size = atoi(optarg); break;
	    case 'n': test_options.packet_count = atoi(optarg); break;
            case 'v': version(argv[0]); exit(0);
	    case 'h':
	    default: usage(argv[0]); exit(0);
	};
    }

    /*
     * Don't do anything if the test provides a target through the dests
     * parameter as well as using -c. They expect the server to behave slightly
     * differently, so we can't tell which the user wants.
     */
    if ( dests && client ) {
        Log(LOG_WARNING, "Option -c not valid when target address already set");
        exit(1);
    }

    //XXX move into common/serverlib.c? use for throughput too
    /* if the -c option is set then get the address into the dests parameter */
    if ( client ) {
        int res;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; // XXX depends on if source is given?
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        dests = (struct addrinfo **)malloc(sizeof(struct addrinfo *));
        if ( (res = getaddrinfo(client, NULL, &hints, &dests[0])) < 0 ) {
            Log(LOG_WARNING, "Failed to resolve '%s': %s", client,
                    gai_strerror(res));
            exit(1);
        }

        /* just take the first address we find */
        count = 1;

        /* set the canonical name to be the address so we can print it later */
        dests[0]->ai_canonname = strdup(client);
    }

    /*
     * Make sure we got a destination, either through the dests parameter
     * or the -c command line argument
     */
    if ( count < 1 || dests == NULL || dests[0] == NULL ) {
        Log(LOG_WARNING, "No destination specified for throughput test");
        exit(1);
    }

#if 0
    /* make sure that the packet size is big enough for our data */
    if ( options.packet_size < MIN_PACKET_LEN ) {
	Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
		options.packet_size, MIN_PACKET_LEN);
	options.packet_size = MIN_PACKET_LEN;
    }
#endif

    /* delay the start by a random amount of perturbate is set */
    if ( test_options.perturbate ) {
	int delay;
	delay = test_options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
	Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
		test_options.perturbate, delay);
	usleep(delay);
    }

    /*
     * Only start the remote server if we expect it to be running as part
     * of amplet2/measured, otherwise it should be already running standalone.
     */
    if ( client == NULL ) {
        int remote_port;
        if ( (remote_port = start_remote_server(AMP_TEST_UDPSTREAM,
                        dests[0], &meta)) == 0 ) {
            Log(LOG_WARNING, "Failed to start remote server, aborting test");
            exit(1);
        }

        Log(LOG_DEBUG, "Got port %d from remote server", remote_port);
        test_options.cport = remote_port;
    }

    run_test(dests[0], &test_options, &socket_options);

    if ( client != NULL ) {
        freeaddrinfo(dests[0]);
        free(dests);
    }

/*
    freeSchedule(&options);
    if ( options.textual_schedule != NULL ) {
        free(options.textual_schedule);
        options.textual_schedule = NULL;
    }
*/

    return 0;
}


void print_udpstream(void *data, uint32_t len) {
}
