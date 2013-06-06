/**
 * The AMP throughput client, see the usage for details.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */
#include <getopt.h>

#include "throughput.h"


#if 0
#undef LOG_DEBUG
#define LOG_DEBUG LOG_WARNING
#endif

int run_throughput(int argc, char *argv[], int count, struct addrinfo **dests);
void print_skeleton(void *data, uint32_t len);
test_t *register_test(void);

/**
 * Prints usage information
 */
static void usage(char *prog) {
                                                                                             /*        | 80char mark*/
    fprintf(stderr, "AMP Throughput Client version %d\n", AMP_THROUGHPUT_TEST_VERSION);
    fprintf(stderr, "Usage: %s [options] [-s testseq] -- addr1 [addr2 ...] \n", prog);
    fprintf(stderr, "NOTE: The test schedule (-s) should be the last argument before -- \n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -r --randomise           Randomise data in every packet sent\n");
    fprintf(stderr, " -p --port <port>         The control port number to use (default=%d)\n", DEFAULT_CONTROL_PORT);
    fprintf(stderr, " -P --test-port <port>    The test port number to use (default=%d)\n", DEFAULT_TEST_PORT);
    fprintf(stderr, " -S --write-size <bytes>  Length of buffer to write (default=%d)\n",(int) DEFAULT_WRITE_SIZE );
    fprintf(stderr, " -o --sndbuf <bytes>      Maximum size of the send (output) buffer\n");
    fprintf(stderr, " -i --rcvbuf <bytes>      Maximum size of the receive (input) buffer\n");
    fprintf(stderr, " -n --nodelay             Disable Nagle's Algorithm (set TCP_NODELAY)\n");
    fprintf(stderr, " -m --tcp-mss <bytes>     Set the Maximum TCP Segment Size\n");
    fprintf(stderr, " -s --schedule <seq>      A valid test schedule such as \"t10000,n,T10000\"\n");
    fprintf(stderr, " -w --disable-web10g      Don't record Web10G results\n");
    fprintf(stderr, " -h -? --help             Print this help\n");
    fprintf(stderr, "Socket options such as rcvbuf, sndbuf, tcp-mss and nodelay will be set on both\n");
    fprintf(stderr, "the client and server. Web10G can be used to check these are set correctly.\n\n");
    fprintf(stderr, "Schedule format:\n");
    fprintf(stderr, "A schedule is a sequence of tests. Each test starts with single character\n");
    fprintf(stderr, "representing it's type. Tests are separated by a single comma ','.\n");
    fprintf(stderr, "Valid types are listed below:\n");
    fprintf(stderr, " s<num_bytes> Run a server -> client test\n");
    fprintf(stderr, " S<num_bytes> Run a client -> server test\n");
    fprintf(stderr, " t<ms>          Run a server -> client test for the time given in milliseconds\n");
    fprintf(stderr, " T<ms>          Run a client -> server test for the time given in milliseconds\n");
    fprintf(stderr, " n              Make a new test connection\n");
    fprintf(stderr, " p<ms>          Time to pause for the time given in milliseconds\n");
    fprintf(stderr, "Example -s \"t1000,T1000\" - Run two tests each for 1 second first S2C then C2S\n");
    fprintf(stderr, "Example -s \"s10000,n,S10000\" - Run two tests S2C then C2S each sending");
    fprintf(stderr, "       10,000 bytes with the connection reset in between\n");
    exit(0);
}



static struct option long_options[] =
    {
        {"randomise", no_argument, 0, 'r'},
        {"port", required_argument, 0, 'p'},
        {"test-port", required_argument, 0, 'P'},
        {"write-size", required_argument, 0, 'S'},
        {"rcvbuf", required_argument, 0, 'i'},
        {"sndbuf", required_argument, 0, 'o'},
        {"nodelay", no_argument, 0, 'n'},
        {"tcp-mss", required_argument, 0, 'm'},
        {"sequence", required_argument, 0, 's'},
        {"disable-web10g", no_argument, 0, 'w'},
        {"help", no_argument, 0, 'h'},
/*      {"c2s-time", required_argument, 0, 'T'},
        {"c2s-packet", required_argument, 0, 'Y'},
        {"s2c-time", required_argument, 0, 't'},
        {"s2c-packet", required_argument, 0, 'y'},
        {"pause", required_argument, 0, 'p'},
        {"new", required_argument, 0, 'N'},*/
        {NULL,0,0,0}
    };



/**
 * Parses a schedule argument and appends the result to the end of the
 * existing schedule. Also places the textual representation of the
 * schedule onto the end of options->textual_schedule.
 *
 * Note: this uses strtok() and will destroy the input argument
 *
 * @param options - A opt_t structure to append to the schedule
 * @param request - A string reprensenting the what is to be added to
 *                  the schedule
 */
static void parseSchedule(struct opt_t * options, char * request) {
    struct test_request_t ** current;
    long arg;
    int noArg;
    char *pch;

    /* Point current to the end of the chain */
    current = &options->schedule;
    while ( *current != NULL ) {
        current = &(*current)->next;
    }

    /* Put the string onto the end of our current sequence */
    if ( options->textual_schedule != NULL ) {
        /* +2 one for null and another for an extra ',' */
        options->textual_schedule = realloc(options->textual_schedule,
              strlen(request) + strlen(options->textual_schedule) + 2);
        strcat(options->textual_schedule, ",");
        strcat(options->textual_schedule, request);
    } else {
        options->textual_schedule = strdup(request);
    }

    Log(LOG_DEBUG, "Parsing the test sequence %s", request);

    pch = strtok (request,",");
    while ( pch != NULL ) {
        /* We assume this is valid
         * And if this isn't isnt marked with request type none anyway */
        *current = (struct test_request_t *) malloc(sizeof(struct test_request_t));
        (*current)->type = TPUT_NULL;
        (*current)->bytes = 0;
        (*current)->duration = 0;
        (*current)->write_size = options->write_size;
        (*current)->randomise = options->randomise;
        (*current)->s_result = (*current)->c_result = NULL;
        (*current)->s_web10g = (*current)->c_web10g = NULL;
        (*current)->next = NULL;

        arg = 0;
        if ( pch[1] == '\0' ) {
            noArg = 1;
        } else {
            noArg = 0;
            arg = atol(pch + 1);
        } //schedule has > 1 character

        switch ( pch[0] ) {
            case 's':
            case 'S':
                (*current)->type = (pch[0] == 's')?TPUT_2_CLIENT:TPUT_2_SERVER;
                (*current)->bytes = arg;
                /* TODO enforce minimum bytes of sizeof(struct packet_t) */
                break;

            case 't':
            case 'T':
                (*current)->type = (pch[0] == 't')?TPUT_2_CLIENT:TPUT_2_SERVER;
                (*current)->duration = arg;
                break;

            case 'p':
            case 'P':
                (*current)->type  = TPUT_PAUSE;
                (*current)->duration = (noArg ? DEFAULT_TPUT_PAUSE : arg);
                break;

            case 'n':
            case 'N':
                (*current)->type = TPUT_NEW_CONNECTION;
                break;

            default:
                Log(LOG_WARNING , "Unknown schedule code in %s (ignored)", pch);
        };

        /* Check test is valid and has a stopping condition*/
        if ( (*current)->type != TPUT_NEW_CONNECTION &&
                (*current)->type != TPUT_NULL ) {
            if ( (*current)->bytes == 0 && (*current)->duration == 0 ) {
                (*current)->type = TPUT_NULL;
                Log(LOG_WARNING,
                        "Invalid test found in schedule ignoring. "
                        "Are you using the correct format?");
            }
        }

        /* Get the next string and move current foward */
        pch = strtok(NULL, ",");
        current = &(*current)->next;
    }
}



/**
 * Free the schedule.
 *
 * @param options - A options structure to free the enclosed schedule.
 */
static void freeSchedule(struct opt_t * options){
    struct test_request_t * cur = options->schedule;

    while ( cur != NULL ) {
        struct test_request_t * temp;
        temp = cur->next;
        free(cur);
        cur = temp;
    }

    options->schedule = NULL;
}



/**
 * Makes a TCP connection to the server.
 *
 * If serv_addr contains a specific a port that is used otherwise a
 * the default port number is used.
 *
 * @param serv_addr
 *              An addrinfo describing the server
 * @param options
 *              The options structure containing the default port number to use
 * @param sendHello
 *              If we should send a hello packet, don't if we're reconnecting
 * @return a valid TCP socket connected to the server. Upon failure -1
 *         is returned.
 */
static int connectToServer(struct addrinfo *serv_addr, struct opt_t *options,
        int port) {
    int sock;

    /* Get a TCP socket - could be either ipv4 or ipv6 based on the addrinfo */
    sock = socket(serv_addr->ai_family, SOCK_STREAM, 0);

    if ( sock != -1 ) {

        /* Set socket options - Nagle MSS, Buffersizes from setup */
        doSocketSetup(options, sock);

        /*
         * If addrinfo has a valid port use that otherwise put in our default.
         * It should be safe to use the IPv4 version here since IPv6 should be
         * in the same place the sizes match
         */
        if ( ((struct sockaddr_in *)serv_addr->ai_addr)->sin_port == 0 ) {
           ((struct sockaddr_in *)serv_addr->ai_addr)->sin_port = htons(port);
        }

        Log(LOG_DEBUG, "Connection has choosen port %d",
                (int)ntohs(
                    ((struct sockaddr_in *)serv_addr->ai_addr)->sin_port));

        if ( connect(sock, serv_addr->ai_addr, serv_addr->ai_addrlen) == -1 ) {
            Log(LOG_WARNING,
                    "connectToServer failed to connect(): %s", strerror(errno));
            close(sock);
            /* return an error socket */
            sock = -1;
        }

    } else {
        Log(LOG_WARNING, "connectToServer failed to create a socket(): %s",
                strerror(errno));
    }
    ((struct sockaddr_in *)serv_addr->ai_addr)->sin_port = 0;

    return sock;
}



/**
 * Sets a given 16 bytes (i.e. a IPv6 address) to the value of sockaddrin
 * IPv4 is converted to a IPv4 mapped IPv6 address.
 *
 * @param ss
 *          Either a sockaddr_in or sockaddr_in6
 * @param addr
 *          The resulting IPv6 address
 */
static void getSockaddrAddr(struct sockaddr_storage *ss, char addr[16]) {

    if ( ss->ss_family == AF_INET ) {
        struct sockaddr_in *s = (struct sockaddr_in *)ss;
        memset(addr,0, 10);
        memset(&addr[10], 0xFF, 2);
        /* Convert from IPv4 mapped address to a ipv6 */
        memcpy(&addr[12], &s->sin_addr.s_addr, 4);
    } else { /* AF_INT6 */
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        memcpy(addr, &s->sin6_addr.s6_addr, 16);
    }

}



/**
 * Make the binary blob for our report
 * Everything here is ordered in Big Endian Byte order
 * +------------------+
 * |                  |
 * | report_header_t  |
 * |                  |
 * +------------------+
 * | Schedule String  | Size defined by report_header_t.test_seq_len including NULL terminator
 * +------------------+
 * |  For every test  |
 * | report_result_t  | From here on repeated for every test C2S or S2C
 * |                  | See report_header_t.count for the number
 * +------------------+
 * | Optional Clients |
 * | report_web10g_t  | Check report_result_t.has_web10g_client
 * |                  |
 * +------------------+
 * | Optional Servers |
 * | report_web10g_t  | Check report_result_t.has_web10g_server
 * |                  |
 * +------------------+
 * + More             + times report_header_t.count
 * + report_header_t's+
 * +~~~~~~~~~~~~~~~~~ +
 */
static void report_results(int sock_fd, struct opt_t *options,
                    uint64_t start_time_ns, uint64_t end_time_ns) {
    struct report_header_t *rh;
    size_t r_size = sizeof(struct report_header_t) +
        strlen(options->textual_schedule) + 1;
    rh = malloc(r_size);
    socklen_t len;
    struct sockaddr_storage ss;
    struct test_request_t *cur;

    /* Build our header up */
    rh->version = REPORT_RESULT_VERSION;
    rh->count = 0; /* Add as we go */
    rh->start_ns = start_time_ns;
    rh->end_ns = end_time_ns;
    rh->test_seq_len = strlen(options->textual_schedule) + 1;

    /* Fill in the addresses of the connection */
    if ( sock_fd != -1 ) {
        len = sizeof(ss);
        getpeername(sock_fd, (struct sockaddr*)&ss, &len);
        getSockaddrAddr(&ss, rh->server_addr);
        len = sizeof(ss);
        getsockname(sock_fd, (struct sockaddr*)&ss, &len);
        getSockaddrAddr(&ss, rh->client_addr);
    } else {
        memset(rh->server_addr, 0, 16);
        memset(rh->client_addr, 0, 16);
    }

    /* Put the Schedule in after the header, its size is variable */
    memcpy(((char *) rh) + sizeof(struct report_header_t),
        options->textual_schedule, rh->test_seq_len);

    /* Loop through the schedule and push the results on to the end */
    for ( cur = options->schedule; cur != NULL ; cur = cur->next ) {
        struct report_result_t *res;
        void *temp;

        switch ( cur->type ) {
            case TPUT_NULL:
                continue;

            case TPUT_NEW_CONNECTION:
            case TPUT_PAUSE:
#if 0
                /* General pattern here set res to point to end of the memory */
                rh = realloc(rh, r_size + sizeof(struct report_result_t));
                res = (struct report_result_t  *) (((char * ) rh) + r_size);
                r_size += sizeof(struct report_result_t);

                res->type = cur->type;
                res->packets = htobe32(0);
                res->write_size = htobe32(0);
                res->duration_ns = htobe64(cur->duration * (uint64_t) 1000000);
                res->has_web10g_server = res->has_web10g_client = 0;
                res->bytes = htobe64(0);

                rh->count++;
                break;
#else
                continue;
#endif
            case TPUT_2_CLIENT:
            case TPUT_2_SERVER:
                if ( cur->c_result == NULL || cur->s_result == NULL ) {
                    /* Something went very wrong */
                    continue;
                }
                rh = realloc(rh, r_size + sizeof(struct report_result_t));
                res = (struct report_result_t  *) (((char * ) rh) + r_size);
                r_size += sizeof(struct report_result_t);

                /* Get the result from the receiving side */
                struct test_result_t * result = cur->type == TPUT_2_CLIENT ?
                            cur->c_result : cur->s_result;

                res->type = cur->type;
                res->packets = htobe32(result->packets);
                res->write_size = htobe32(result->write_size);
                res->duration_ns = htobe64(result->end_ns - result->start_ns);
                res->bytes = htobe64(result->bytes);
                rh->count++;

                /* Order matters always put client first */
                res->has_web10g_client = cur->c_web10g == NULL ? 0 : 1;
                res->has_web10g_server = cur->s_web10g == NULL ? 0 : 1;

                /* Our web10g data is already converted to big endian */
                if ( cur->c_web10g ) {
                    rh = realloc(rh, r_size + sizeof(struct report_web10g_t));
                    temp = ((char * ) rh) + r_size;
                    r_size += sizeof(struct report_web10g_t);
                    memcpy(temp, cur->c_web10g, sizeof(struct report_web10g_t));
                }

                if ( cur->s_web10g ) {
                    rh = realloc(rh, r_size + sizeof(struct report_web10g_t));
                    temp = ((char * ) rh) + r_size;
                    r_size += sizeof(struct report_web10g_t);
                    memcpy(temp, cur->s_web10g, sizeof(struct report_web10g_t));
                }
                break;
        };

        if ( cur->s_result ) {
            free(cur->s_result);
            cur->s_result = NULL;
        }
        if ( cur->c_result ) {
            free(cur->c_result);
            cur->c_result = NULL;
        }
        if ( cur->s_web10g ) {
            free(cur->s_web10g);
            cur->s_web10g = NULL;
        }
        if ( cur->c_web10g ) {
            free(cur->c_web10g);
            cur->c_web10g = NULL;
        }
    }

    /* Convert the header to big endian byte order */
    rh->version = htobe32(rh->version);
    rh->count = htobe32(rh->count);
    rh->start_ns = htobe64(rh->start_ns);
    rh->end_ns = htobe64(rh->end_ns);
    rh->test_seq_len = htobe32(rh->test_seq_len);

    report(AMP_TEST_THROUGHPUT, start_time_ns / (uint64_t) 1000000000,
            (void*)rh, r_size);
    free(rh);
}



/**
 * Runs through the provided schedule on every IP address it's given
 *
 * @param server_address Address of the server to connect to and run the test
 * @param options A copy of the program options which also contains the sequence
 *
 * @return 0 if successful, otherwise -1 on failure
 */
static int runSchedule(struct addrinfo * serv_addr, struct opt_t * options) {
    int control_socket = -1;
    int test_socket = -1;
    struct packet_t packet;
    uint64_t start_time_ns;
    struct opt_t srv_opts = {0};
    uint16_t actual_test_port = 0;

    /* Loop through the schedule */
    struct test_request_t *cur;

    memset(&packet, 0, sizeof(packet));

    /* Connect to the server control socket */
    control_socket = connectToServer(serv_addr, &srv_opts, options->cport);
    start_time_ns = timeNanoseconds();
    if ( control_socket == -1 ) {
        Log(LOG_ERR, "Cannot connect to the server control");
        goto errorCleanup;
    }

    /* Send version info along with socket preference */
    if ( sendHelloPacket(control_socket, options) < 0 ) {
        goto errorCleanup;
    }
    /* Wait test socket to become ready */
    if ( readPacket(control_socket, &packet, NULL) == 0 ) {
        Log(LOG_ERR, "Failed to read ready packet");
        goto errorCleanup;
    }
    if ( readReadyPacket(&packet, &actual_test_port) != 0 ) {
        goto errorCleanup;
    }

    /* Connect the test socket */
    test_socket = connectToServer(serv_addr, options, actual_test_port);
    if ( test_socket == -1 ) {
        Log(LOG_ERR, "Cannot connect to the server testsocket");
        goto errorCleanup;
    }


    for ( cur = options->schedule; cur != NULL ; cur = cur->next ) {
        switch ( cur->type ) {
            case TPUT_NULL:
                continue;

            case TPUT_PAUSE:
                Log(LOG_INFO, "Pausing for %"PRIu32"milliseconds",
                        cur->duration);
                sleep((int)(cur->duration / 1000));
                usleep((cur->duration%1000) * 1000);
                continue;

            case TPUT_NEW_CONNECTION:
                Log(LOG_INFO, "Asking the Server to renew the connection");
                if ( sendResetPacket(control_socket) < 0 ) {
                    Log(LOG_ERR, "Failed to send reset packet");
                    goto errorCleanup;
                }
                /* Wait for server to start listening */
                if ( readPacket(test_socket, &packet, NULL) != 0 ) {
                    Log(LOG_ERR, "TPUT_NEW_CONNECTION expected the TCP connection to be closed in this direction");
                    goto errorCleanup;
                }
                close(test_socket);
                /* Read the actual port to use */
                if ( readPacket(control_socket, &packet, NULL) == 0 ) {
                    Log(LOG_ERR, "Failed to read packet");
                    goto errorCleanup;
                }
                if ( readReadyPacket(&packet , &actual_test_port) != 0 ) {
                    goto errorCleanup;
                }
                /* Open up a new one */
                test_socket = connectToServer(serv_addr, options,
                        actual_test_port);
                if ( test_socket == -1 ) {
                    Log(LOG_ERR, "Failed to open a new connection");
                    goto errorCleanup;
                }
                continue;

            case TPUT_2_CLIENT:
                Log(LOG_INFO, "Starting Server to Client Throughput test");
                /* Request a test from the server */
                if ( sendRequestTestPacket(control_socket, cur) < 0 ) {
                    goto errorCleanup;
                }

                /* Get ready for results */
                cur->c_result = malloc(sizeof(struct test_result_t));
                cur->s_result = malloc(sizeof(struct test_result_t));
                memset(cur->c_result, 0, sizeof(struct test_result_t));
                memset(cur->s_result, 0, sizeof(struct test_result_t));

                /* Receive the test */
                if ( incomingTest(test_socket, cur->c_result) != 0 ) {
                    Log(LOG_ERR, "Somthing went wrong when receiving a incoming test from the server");
                    goto errorCleanup;
                }

                /* No errors so we should have a valid result */
                if ( !options->disable_web10g ) {
                    cur->c_web10g = getWeb10GSnap(test_socket);
                }

                /* Get servers result - might even have web10g attached */
                readPacket(control_socket, &packet, (char **) &cur->s_web10g);
                if ( readResultPacket(&packet, cur->s_result) != 0 ) {
                    return -1;
                }
                Log(LOG_DEBUG, "Received results of test from server");
                continue;

            case TPUT_2_SERVER:
                Log(LOG_INFO, "Starting Client to Server Throughput test");
                cur->c_result = malloc(sizeof(struct test_result_t));
                cur->s_result = malloc(sizeof(struct test_result_t));
                memset(cur->c_result, 0, sizeof(struct test_result_t));
                memset(cur->s_result, 0, sizeof(struct test_result_t));

                /* Tell the server we are starting a test */
                sendFinalDataPacket(control_socket);
                /* Wait for it get ready */
                if ( readPacket(control_socket, &packet, NULL) == 0 ) {
                    Log(LOG_ERR, "Unexpected response from server");
                    goto errorCleanup;
                }
                if ( readReadyPacket(&packet, &actual_test_port) != 0 ) {
                    goto errorCleanup;
                }
                if ( sendPackets(test_socket, cur, cur->c_result) == 0 ) {
                    Log(LOG_DEBUG, "Finished sending - now getting results");

                    if ( !options->disable_web10g ) {
                        cur->c_web10g = getWeb10GSnap(test_socket);
                    }
                    if ( !readPacket(control_socket, &packet,
                                (char **) &cur->s_web10g) ) {
                         Log(LOG_ERR,"Failed to get results");
                         goto errorCleanup;
                    }

                    if ( readResultPacket(&packet, cur->s_result) != 0 ) {
                        goto errorCleanup;
                    }

                    Log(LOG_DEBUG, "Got results from server %" PRIu32
                            " %" PRIu32 " %" PRIu64 " %" PRIu64,
                                    packet.types.result.packets,
                                    packet.types.result.write_size,
                                    packet.types.result.duration_ns,
                                    packet.types.result.bytes);
                } else {
                    Log(LOG_ERR, "Failed to sent packets to the server");
                    goto errorCleanup;
                }
                continue;

            default:
                Log(LOG_WARNING,
                        "runSchedule found an invalid test_request_t->type");
                continue;
        }
    }


    /**
     * Now for the fun bit, results. At this point the schedule has
     * the results of the tests attached to it stored in malloc'd mem:
     * s_result c_result c_web10g s_web10g (C= client==us S= Server )
     *
     * We will report this set of results then we can finish
     */
    report_results(control_socket, options, start_time_ns , timeNanoseconds());

    Log(LOG_INFO, "Closing test");
    if( sendClosePacket(control_socket) < 0)
         Log(LOG_WARNING, "Failed to send close message");

    close(control_socket);
    close(test_socket);

    return 0;
errorCleanup :
    /* See if we can report something anyway */
    report_results(control_socket, options, start_time_ns , timeNanoseconds());

    if ( control_socket != -1 ) {
        close(control_socket);
    }
    if ( test_socket != -1 ) {
        close(test_socket);
    }
    return -1;
}



/**
 * The main function of the throughput client test.
 */
int run_throughput(int argc, char *argv[], int count, struct addrinfo **dests) {
    struct opt_t options;
    int opt;
    int i;
    char modifiable[] = DEFAULT_TEST_SCHEDULE;
    int option_index = 0;

    Log(LOG_DEBUG, "Starting throughput test - got given %d addresses", count);
    Log(LOG_INFO, "Our Structure sizes Pkt:%d RptHdr:%d RptRes:%d Rpt10G:%d",
            sizeof(struct packet_t),
            sizeof(struct report_header_t),
            sizeof(struct report_result_t),
            sizeof(struct report_web10g_t)
       );

    /* set some sensible defaults */
    options.write_size = DEFAULT_WRITE_SIZE;
    options.randomise = 0;
    options.sock_rcvbuf = 0;
    options.sock_sndbuf = 0;
    options.sock_disable_nagle = 0;
    options.sock_mss = 0;
    options.cport = DEFAULT_CONTROL_PORT;
    options.tport = DEFAULT_TEST_PORT;
    options.disable_web10g = 0;
    options.schedule = NULL;
    options.textual_schedule = NULL;
    options.reuse_addr = 0;

    while ( (opt = getopt_long(argc, argv, "?hp:P:rs:o:i:nm:wS:",
                    long_options, &option_index)) != -1 ) {

        switch ( opt ) {
            case 'p': options.cport = atoi(optarg); break;
            case 'P': options.tport = atoi(optarg); break;
            case 'r': options.randomise = 1; break;
            case 'S': options.write_size = atoi(optarg); break;
            case 's': parseSchedule(&options, optarg); break;
            case 'o': options.sock_sndbuf = atoi(optarg); break;
            case 'i': options.sock_rcvbuf = atoi(optarg); break;
            case 'n': options.sock_disable_nagle = 1; break;
            case 'm': options.sock_mss = atoi(optarg); break;
            case 'w': options.disable_web10g = 1; break;
            case 'h':
            case '?':
            default: usage(argv[0]); exit(0);
        };
    }

    /* make sure write size is sensible */
    if ( options.write_size < sizeof(struct packet_t) ||
            options.write_size > MAX_MALLOC ) {
        Log(LOG_ERR, "Write size invalid, should be %d < x < %d, got %d",
                sizeof(struct packet_t), MAX_MALLOC, options.write_size);
        return 1;
    }

    /* If there is no test schedule set it to use the default */
    if ( options.schedule == NULL ) {
        Log(LOG_DEBUG, "No test schedule using default");
        parseSchedule(&options, modifiable);
    }

    /* Print out our schedule */
    printSchedule(options.schedule);

    /* Loop through all the addresses we are asked to test */
    for ( i = 0; i < count; i++ ) {
        runSchedule(dests[i], &options);
    }

    freeSchedule(&options);
    if ( options.textual_schedule != NULL ) {
        free(options.textual_schedule);
        options.textual_schedule = NULL;
    }

    return 0;
}



/**
 * Print out a speed in a factor of bits per second
 * Kb = 1000 * b
 * Mb = 1000 * Kb etc
 */
static void printSpeed(uint64_t time_ns, uint64_t bytes){
    double x_per_sec = ((double)bytes * 8.0) / ((double) time_ns / 1e9);

    if ( x_per_sec > 1000 ) {
        x_per_sec /= 1000;
    } else {
        printf("--- Speed: %lf%s\n", x_per_sec, "Bits/s");
        return;
    }
    if ( x_per_sec > 1000 ) {
        x_per_sec /= 1000;
    } else {
        printf("--- Speed: %lf%s\n", x_per_sec, "Kb/s");
        return;
    }
    if ( x_per_sec > 1000 ) {
        x_per_sec /= 1000;
    } else {
        printf("--- Speed: %lf%s\n", x_per_sec, "Mb/s");
        return;
    }
    /* Realistically not going to be Tb/s */
    printf("--- Speed: %lf%s\n", x_per_sec, "Gb/s");
}



/**
 * Print back our data blob that we made report_results.
 * Remember this is all in big endian byte order
 */
static void print_throughput(void *data, uint32_t len) {
    char name[128];
    struct report_header_t * rh = data;
    uint32_t count = 1;
    char *place;

    inet_ntop(AF_INET6, &rh->server_addr, name, sizeof(name));
    printf("\n- Got the results test(s) to server address %s \n", name);

    inet_ntop(AF_INET6, &rh->client_addr, name, sizeof(name));
    printf("- We connected on the interface %s\n", name);
    printf("- Found %d headers\n", be32toh(rh->count));

    /* Read the report header results */
    place = (char *) (rh+1);
    printf("- Test schedule was %s\n\n", place);
    place += be32toh(rh->test_seq_len);

    /* Now read back the acutal results */
    while ( count <= be32toh(rh->count) ) {
        struct report_result_t *  rr;
        rr = (struct report_result_t *) place;
        place += sizeof(struct report_result_t);

        printf("\n\n--- Test run %d ---\n", count);
        switch ( rr->type ) {
            case TPUT_2_CLIENT:
                printf("--- Test type server -> client \n");
                break;
            case TPUT_2_SERVER:
                printf("--- Test type client -> server \n");
                break;
            case TPUT_PAUSE:
                printf("--- Test type pause\n");
                break;
            case TPUT_NEW_CONNECTION:
                printf("--- Test type reset connection\n");
                break;
            default:
                printf("--- Test type unknown %d \n", (int) rr->type);
        }
        printf("--- Packets sent/received during test %" PRIu32 "\n",
                be32toh(rr->packets));
        printf("--- Write Size for the test %" PRIu32 "\n",
                be32toh(rr->write_size));
        printf("--- Test duration %lf secs \n",
                (double)be64toh(rr->duration_ns) / 1e9);
        printf("--- Test %" PRIu64 " bytes\n", be64toh(rr->bytes));
        printSpeed(be64toh(rr->duration_ns), be64toh(rr->bytes));

        if ( rr->has_web10g_client ) {
            printf("--- Found web10g vars from the client\n");
            print_web10g((struct report_web10g_t *) place);
            place += sizeof(struct report_web10g_t);
        } else {
            printf("--- No web10g vars from the client \n");
        }

        if ( rr->has_web10g_server ) {
            printf("--- Found web10g vars from the server\n");
            print_web10g((struct report_web10g_t *) place);
            place += sizeof(struct report_web10g_t);
        } else {
            printf("--- No web10g vars from the server\n");
        }
        count++;
    }
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in test.h */
    new_test->id = AMP_TEST_THROUGHPUT;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("throughput");

    /* how many targets a single instance of this test can have  - Only 1 */
    new_test->max_targets = 0;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_throughput;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_throughput;

    return new_test;
}
