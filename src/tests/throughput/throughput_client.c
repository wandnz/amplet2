/**
 * The AMP throughput client, see the usage for details.
 *
 * @author Richard Sanger
 * Based upon the old AMP throughput test
 */
#include <getopt.h>
#include <assert.h>

#include "serverlib.h"
#include "throughput.h"
#include "throughput.pb-c.h"



/**
 * Debug print of the schedule
 */
static void printSchedule(struct test_request_t *schedule) {
   struct test_request_t *cur;
   Log(LOG_DEBUG, "Printing out schedule");
   for ( cur = schedule; cur != NULL ; cur = cur->next ) {
       switch ( cur->type ) {
           case TPUT_NULL: Log(LOG_DEBUG, "Found a TPUT_NULL"); break;
           case TPUT_PAUSE: Log(LOG_DEBUG, "Found a TPUT_PAUSE"); break;
           case TPUT_NEW_CONNECTION:
                            Log(LOG_DEBUG, "Found a TPUT_NEW_CONNECTION");
                            break;
           case TPUT_2_CLIENT: Log(LOG_DEBUG, "Found a TPUT_2_CLIENT"); break;
           case TPUT_2_SERVER: Log(LOG_DEBUG, "Found a TPUT_2_SERVER"); break;
           default : Log(LOG_DEBUG, "Found a bad type"); break;
       }
       Log(LOG_DEBUG, "bytes:%d duration:%d writesize:%d randomise:%d",
               cur->bytes, cur->duration, cur->write_size, cur->randomise);
   }
   Log(LOG_DEBUG, "Finished schedule");
}




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
static void parseSchedule(struct opt_t *options, char *request) {
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
        /*
         * We assume this is valid and if this isn't then it is marked with
         * request type none anyway
         */
        *current = (struct test_request_t *)
            malloc(sizeof(struct test_request_t));
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
static void freeSchedule(struct opt_t *options){
    struct test_request_t *item = options->schedule;
    struct test_request_t *tmp;

    while ( item != NULL ) {
        tmp = item;
        item = item->next;

        if ( tmp->s_result ) {
            free(tmp->s_result);
            tmp->s_result = NULL;
        }
        if ( tmp->c_result ) {
            free(tmp->c_result);
            tmp->c_result = NULL;
        }
        if ( tmp->s_web10g ) {
            free(tmp->s_web10g);
            tmp->s_web10g = NULL;
        }
        if ( tmp->c_web10g ) {
            free(tmp->c_web10g);
            tmp->c_web10g = NULL;
        }
        free(tmp);
    }

    options->schedule = NULL;
}






/*
 *
 */
static void report_results(uint64_t start_time, struct addrinfo *dest,
        struct opt_t *options) {

    Amplet2__Throughput__Report msg = AMPLET2__THROUGHPUT__REPORT__INIT;
    Amplet2__Throughput__Header header = AMPLET2__THROUGHPUT__HEADER__INIT;
    Amplet2__Throughput__Item **reports = NULL;
    struct test_request_t *item;
    unsigned int i;
    void *buffer;
    int len;

    /* populate the header with all the test options */
    header.schedule = options->textual_schedule;
    header.has_family = 1;
    header.family = dest->ai_family;
    header.has_write_size = 1;
    header.write_size = options->write_size;
    header.name = address_to_name(dest);
    header.has_address = copy_address_to_protobuf(&header.address, dest);

    /* build up the repeated reports section with each of the results */
    for ( i = 0, item = options->schedule; item != NULL; item = item->next ) {
        /* only report on schedule items that send data */
        if ( item->type != TPUT_2_CLIENT && item->type != TPUT_2_SERVER ) {
            continue;
        }

        if ( item->c_result == NULL || item->s_result == NULL ) {
            continue;
        }

        reports = realloc(reports, sizeof(Amplet2__Throughput__Item*) * (i+1));
        reports[i] = report_schedule(item);
        i++;
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = i;

    /* pack all the results into a buffer for transmitting */
    len = amplet2__throughput__report__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__throughput__report__pack(&msg, buffer);

    /* send the packed report object */
    report(AMP_TEST_THROUGHPUT, start_time, (void*)buffer, len);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < msg.n_reports; i++ ) {
        free(reports[i]);
    }

    free(reports);
    free(buffer);
}



/**
 * Runs through the provided schedule on every IP address it's given
 *
 * @param server_address Address of the server to connect to and run the test
 * @param options A copy of the program options which also contains the sequence
 *
 * @return 0 if successful, otherwise -1 on failure
 */
static int runSchedule(struct addrinfo *serv_addr, struct opt_t *options,
        struct temp_sockopt_t_xxx *socket_options) {
    int control_socket;
    int test_socket = -1;
    struct packet_t packet;
    uint64_t start_time_ns;
    struct temp_sockopt_t_xxx srv_opts;
    uint16_t actual_test_port = 0;
    ProtobufCBinaryData data;
    Amplet2__Throughput__Item *results = NULL;

    /* Loop through the schedule */
    struct test_request_t *cur;

    memset(&packet, 0, sizeof(packet));
    memset(&srv_opts, 0, sizeof(srv_opts));
    srv_opts.device = options->device;
    srv_opts.sourcev4 = options->sourcev4;
    srv_opts.sourcev6 = options->sourcev6;
    srv_opts.socktype = SOCK_STREAM;
    srv_opts.protocol = IPPROTO_TCP;

    //XXX i think sourcev4 and source6 and device already exist in this?
    socket_options->cport = options->cport;//XXX
    socket_options->tport = options->tport;//XXX
    socket_options->sock_mss = options->sock_mss;//XXX
    socket_options->sock_disable_nagle = options->sock_disable_nagle;//XXX
    socket_options->sock_rcvbuf = options->sock_rcvbuf;//XXX
    socket_options->sock_sndbuf = options->sock_sndbuf;//XXX

    socket_options->socktype = SOCK_STREAM;
    socket_options->protocol = IPPROTO_TCP;

    /* Connect to the server control socket */
    control_socket = connect_to_server(serv_addr, &srv_opts, options->cport);
    start_time_ns = timeNanoseconds();
    if ( control_socket == -1 ) {
        Log(LOG_ERR, "Cannot connect to the server control");
        goto errorCleanup;
    }

    if ( send_control_hello(control_socket, build_hello(options)) < 0 ) {
        Log(LOG_WARNING, "Failed to send HELLO packet, aborting");
        goto errorCleanup;
    }

    /* Wait test socket to become ready */
    if ( read_control_ready(control_socket, &socket_options->tport) < 0 ) {
        Log(LOG_WARNING, "Failed to read READY packet, aborting");
        close(control_socket);
        return -1;
    }

    actual_test_port = socket_options->tport;//XXX

    /* Connect the test socket */
    test_socket = connect_to_server(serv_addr, socket_options, actual_test_port);
    if ( test_socket == -1 ) {
        Log(LOG_ERR, "Cannot connect to the server testsocket");
        goto errorCleanup;
    }


    for ( cur = options->schedule; cur != NULL ; cur = cur->next ) {
        switch ( cur->type ) {
            case TPUT_NULL:
                continue;

            case TPUT_PAUSE:
                Log(LOG_DEBUG, "Pausing for %" PRIu32 "milliseconds",
                        cur->duration);
                sleep((int)(cur->duration / 1000));
                usleep((cur->duration % 1000) * 1000);
                continue;

            case TPUT_NEW_CONNECTION:
                Log(LOG_DEBUG, "Asking the Server to renew the connection");
                if ( send_control_renew(control_socket) < 0 ) {
                    Log(LOG_ERR, "Failed to send reset packet");
                    goto errorCleanup;
                }
                /* Wait for server to start listening */
                if ( readPacket(test_socket, &packet, NULL) != 0 ) {
                    Log(LOG_ERR, "TPUT_NEW_CONNECTION expected the TCP "
                            "connection to be closed in this direction");
                    goto errorCleanup;
                }
                close(test_socket);
                /* Read the actual port to use */
                if ( read_control_ready(control_socket,
                            &socket_options->tport) < 0 ) {
                    Log(LOG_WARNING, "Failed to read READY packet, aborting");
                    close(control_socket);
                    return -1;
                }
                actual_test_port = socket_options->tport;//XXX
                /* Open up a new one */
                test_socket = connect_to_server(serv_addr, socket_options,
                        actual_test_port);
                if ( test_socket == -1 ) {
                    Log(LOG_ERR, "Failed to open a new connection");
                    goto errorCleanup;
                }
                continue;

            case TPUT_2_CLIENT:
                Log(LOG_DEBUG, "Starting Server to Client Throughput test");
                /* Request a test from the server */
#if 0
                if ( send_control_send(control_socket, 0, cur->duration,
                            cur->write_size, cur->bytes) < 0 ) {
#endif
                if ( send_control_send(control_socket, build_send(cur)) < 0 ) {
                    goto errorCleanup;
                }

                /* Get ready for results */
                cur->c_result = malloc(sizeof(struct test_result_t));
                cur->s_result = malloc(sizeof(struct test_result_t));
                memset(cur->c_result, 0, sizeof(struct test_result_t));
                memset(cur->s_result, 0, sizeof(struct test_result_t));

                /* Receive the test */
                if ( incomingTest(test_socket, cur->c_result) != 0 ) {
                    Log(LOG_ERR, "Something went wrong when receiving an "
                            "incoming test from the server");
                    goto errorCleanup;
                }

                /* No errors so we should have a valid result */
                //XXX web10g
                //if ( !options->disable_web10g ) {
                //    cur->c_web10g = getWeb10GSnap(test_socket);
                //}

                /* Get servers result - might even have web10g attached */
                if ( read_control_result(control_socket, &data) < 0 ) {
                    Log(LOG_WARNING, "Failed to read RESULT packet, aborting");
                    return -1;
                }
                results = amplet2__throughput__item__unpack(NULL, data.len,
                        data.data);
                /* XXX extracting this now cause it's easier :( */
                /* XXX are ->done or ->packets every actually used? internally
                 * but no reason to transmit I believe
                 */
                cur->s_result->start_ns = 0;
                cur->s_result->end_ns = results->duration;
                cur->s_result->bytes = results->bytes;
                free(data.data);
                amplet2__throughput__item__free_unpacked(results, NULL);
                Log(LOG_DEBUG, "Received results of test from server");
                continue;

            case TPUT_2_SERVER:
                Log(LOG_DEBUG, "Starting Client to Server Throughput test");
                cur->c_result = malloc(sizeof(struct test_result_t));
                cur->s_result = malloc(sizeof(struct test_result_t));
                memset(cur->c_result, 0, sizeof(struct test_result_t));
                memset(cur->s_result, 0, sizeof(struct test_result_t));

                /* Tell the server we are starting a test */
                send_control_receive(control_socket, 0);
                /* Wait for it get ready */
                if ( read_control_ready(control_socket,
                            &socket_options->tport) < 0 ) {
                    Log(LOG_WARNING, "Failed to read READY packet, aborting");
                    close(control_socket);
                    return -1;
                }

                if ( sendPackets(test_socket, cur, cur->c_result) == 0 ) {
                    Log(LOG_DEBUG, "Finished sending - now getting results");

                    //XXX web10g
                    //if ( !options->disable_web10g ) {
                    //    cur->c_web10g = getWeb10GSnap(test_socket);
                    //}
                    //if ( !readPacket(control_socket, &packet,
                    //            (char **) &cur->s_web10g) ) {
                    //    Log(LOG_ERR,"Failed to get results");
                    //    goto errorCleanup;
                    //}

                    if ( read_control_result(control_socket, &data) < 0 ) {
                        Log(LOG_WARNING, "Failed to read RESULT packet, aborting");
                        return -1;
                    }
                    results = amplet2__throughput__item__unpack(NULL, data.len,
                            data.data);
                    /* XXX extracting this now cause it's easier :( */
                    cur->s_result->start_ns = 0;
                    cur->s_result->end_ns = results->duration;
                    cur->s_result->bytes = results->bytes;
                    free(data.data);
                    amplet2__throughput__item__free_unpacked(results, NULL);
/*
                    Log(LOG_DEBUG, "Got results from server %" PRIu32
                            " %" PRIu32 " %" PRIu64 " %" PRIu64,
                            packet.types.result.packets,
                            packet.types.result.write_size,
                            packet.types.result.duration_ns,
                            packet.types.result.bytes);
 */
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
    report_results(start_time_ns / 1000000000, serv_addr, options);

    Log(LOG_DEBUG, "Closing test");
    if ( send_control_close(control_socket) < 0 ) {
         Log(LOG_WARNING, "Failed to send close message");
    }

    close(control_socket);
    close(test_socket);

    return 0;
errorCleanup :
    /* See if we can report something anyway */
    report_results(start_time_ns / 1000000000, serv_addr, options);

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
int run_throughput_client(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    struct opt_t test_options;
    struct temp_sockopt_t_xxx socket_options;
    amp_test_meta_t meta;
    int opt;
    int option_index = 0;
    extern struct option long_options[];
    char *client;
    int duration = -1;
    enum tput_schedule_direction direction = DIRECTION_NOT_SET;

    Log(LOG_DEBUG, "Running throughput test as client");

    /* set some sensible defaults */
    memset(&test_options, 0, sizeof(test_options));
    test_options.write_size = DEFAULT_WRITE_SIZE;
    test_options.randomise = 0;
    test_options.sock_rcvbuf = 0;
    test_options.sock_sndbuf = 0;
    test_options.sock_disable_nagle = 0;
    test_options.sock_mss = 0;
    test_options.cport = DEFAULT_CONTROL_PORT;
    test_options.tport = DEFAULT_TEST_PORT;
    test_options.disable_web10g = 0;
    test_options.schedule = NULL;
    test_options.textual_schedule = NULL;
    test_options.reuse_addr = 0;

    /* TODO free these when done? */
    memset(&socket_options, 0, sizeof(socket_options));
    socket_options.sourcev4 = NULL;
    socket_options.sourcev6 = NULL;
    socket_options.device = NULL;
    client = NULL;

    memset(&meta, 0, sizeof(meta));

    while ( (opt = getopt_long(argc, argv, "?hp:P:rz:o:i:Nm:wS:c:d:4:6:I:t:Z:",
                    long_options, &option_index)) != -1 ) {

        switch ( opt ) {
            case 'Z': /* option does nothing for this test */ break;
            case '4': socket_options.sourcev4 =
                            get_numeric_address(optarg, NULL);
                      meta.sourcev4 = optarg;
                      break;
            case '6': socket_options.sourcev6 =
                            get_numeric_address(optarg, NULL);
                      meta.sourcev4 = optarg;
                      break;
            case 'I': socket_options.device = meta.interface = optarg; break;
            /* case 'B': for iperf compatability? */
            case 'c': client = optarg; break;
            case 'p': test_options.cport = atoi(optarg); break;
            case 'P': test_options.tport = atoi(optarg); break;
            case 'r': test_options.randomise = 1; break;
            case 'z': test_options.write_size = atoi(optarg); break;
            /* TODO if this isn't last, some options use default values! */
            case 'S': parseSchedule(&test_options, optarg); break;
            case 'o': test_options.sock_sndbuf = atoi(optarg); break;
            case 'i': test_options.sock_rcvbuf = atoi(optarg); break;
            case 'N': test_options.sock_disable_nagle = 1; break;
            case 'M': test_options.sock_mss = atoi(optarg); break;
            case 'w': test_options.disable_web10g = 1; break;
            case 't': duration = atoi(optarg); break;
            case 'd': direction = atoi(optarg); break;
            case 'h':
            case '?':
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

    /* make sure write size is sensible */
    if ( test_options.write_size < sizeof(struct packet_t) ||
            test_options.write_size > MAX_MALLOC ) {
        Log(LOG_ERR, "Write size invalid, should be %d < x < %d, got %d",
                sizeof(struct packet_t), MAX_MALLOC, test_options.write_size);
        exit(1);
    }

    /* schedule can't be set if direction and duration are also set */
    if ( duration > 0 && direction != DIRECTION_NOT_SET &&
            test_options.schedule ) {
        Log(LOG_ERR,
                "Schedule string given as well as duration/direction flags");
        exit(1);
    }

    /*
     * If there is no test schedule, then try to make one from the other
     * flags that were given, or use a default schedule.
     */
    if ( test_options.schedule == NULL ) {
        char sched[128];

        Log(LOG_DEBUG, "No test schedule, creating one");

        /*
         * This is seconds because that's easier for the user to type on the
         * command line, while in the schedule things are in ms (should
         * probably move the schedule to seconds too, who wants to run tests
         * for fractions of seconds?)
         */
        if ( duration < 0 ) {
            duration = DEFAULT_TEST_DURATION;
        }

        Log(LOG_DEBUG, "Using duration of %d seconds", duration);

        /* and put it back into milliseconds */
        duration *= 1000;

        /*
         * This is really a hidden option to make life easier when scheduling
         * tests through the web interface. If it was more user facing then
         * it should be a bit nicer and use better textual values (which would
         * involve strcmp and not work as a switch statement).
         */
        switch ( direction ) {
            case CLIENT_TO_SERVER:
                snprintf(sched, sizeof(sched), "T%d", duration);
                break;
            case SERVER_TO_CLIENT:
                snprintf(sched, sizeof(sched), "t%d", duration);
                break;
            case CLIENT_THEN_SERVER:
                snprintf(sched, sizeof(sched), "T%d,n,t%d", duration, duration);
                break;
            case SERVER_THEN_CLIENT:
                snprintf(sched, sizeof(sched), "t%d,n,T%d", duration, duration);
                break;
            default:
                Log(LOG_WARNING, "Using default direction client -> server");
                snprintf(sched, sizeof(sched), "T%d", duration);
                break;
        };

        Log(LOG_DEBUG, "Generated schedule: '%s'", sched);

        /* create the schedule list as if this was a normal schedule string */
        parseSchedule(&test_options, sched);
    }

    /* Print out our schedule */
    printSchedule(test_options.schedule);

    /*
     * Only start the remote server if we expect it to be running as part
     * of amplet2/measured, otherwise it should be already running standalone.
     */
    if ( client == NULL ) {
        int remote_port;
        if ( (remote_port = start_remote_server(AMP_TEST_THROUGHPUT,
                        dests[0], &meta)) == 0 ) {
            Log(LOG_WARNING, "Failed to start remote server, aborting test");
            exit(1);
        }

        Log(LOG_DEBUG, "Got port %d from remote server", remote_port);
        test_options.cport = remote_port;
    }
    runSchedule(dests[0], &test_options, &socket_options);

    if ( client != NULL ) {
        freeaddrinfo(dests[0]);
        free(dests);
    }

    freeSchedule(&test_options);
    if ( test_options.textual_schedule != NULL ) {
        free(test_options.textual_schedule);
        test_options.textual_schedule = NULL;
    }

    return 0;
}



/*
 *
 */
static void printSize(uint64_t bytes) {
    double scaled = (double)bytes;
    char *units[] = {"bytes", "KBytes", "MBytes", "GBytes", NULL};
    char **unit;

    for ( unit = units; *unit != NULL; unit++ ) {
        if ( scaled < 1024 ) {
            printf(" %.02lf %s", scaled, *unit);
            return;
        }
        scaled = scaled / 1024.0;
    }

    printf(" %.02lf TBytes", scaled);
}



/*
 *
 */
static void printDuration(uint64_t time_ns) {
    printf(" in %.02lf seconds", ((double)time_ns) / 1000000000);
}



/**
 * Print out a speed in a factor of bits per second
 * Kb = 1000 * b
 * Mb = 1000 * Kb etc
 */
static void printSpeed(uint64_t bytes, uint64_t time_ns) {
    double x_per_sec = ((double)bytes * 8.0) / ((double) time_ns / 1e9);
    char *units[] = {"bits", "Kbits", "Mbits", "Gbits", NULL};
    char **unit;

    for ( unit = units; *unit != NULL; unit++ ) {
        if ( x_per_sec < 1000 ) {
            printf(" at %.02lf %s/sec", x_per_sec, *unit);
            return;
        }
        x_per_sec = x_per_sec / 1000;
    }

    printf(" at %.02lf Tb/s", x_per_sec);
}



/**
 * Print back our data blob that we made report_results.
 * Remember this is all in big endian byte order
 *
 * TODO make this output a lot nicer
 */
void print_throughput(void *data, uint32_t len) {
    Amplet2__Throughput__Report *msg;
    Amplet2__Throughput__Item *item;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(data != NULL);

    /* unpack all the data */
    msg = amplet2__throughput__report__unpack(NULL, len, data);

    assert(msg);
    assert(msg->header);

    /* print global configuration options */
    printf("\n");
    inet_ntop(msg->header->family, msg->header->address.data, addrstr,
            INET6_ADDRSTRLEN);
    printf("AMP throughput test to %s (%s)\n", msg->header->name, addrstr);
    printf("writesize:%" PRIu32 " schedule:%s\n", msg->header->write_size,
            msg->header->schedule);

    for ( i=0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];
        if ( item->direction ==
                AMPLET2__THROUGHPUT__ITEM__DIRECTION__SERVER_TO_CLIENT ) {
            printf("  * server -> client:");
        } else if ( item->direction ==
                AMPLET2__THROUGHPUT__ITEM__DIRECTION__CLIENT_TO_SERVER ) {
            printf("  * client -> server:");
        } else {
            continue;
        }

        printSize(item->bytes);
        printDuration(item->duration);
        printSpeed(item->bytes, item->duration);
        printf("\n");
#if 0
        if ( item->has_web10g_client ) {
        }

        if ( item->has_web10g_server ) {
        }
#endif
    }

    amplet2__throughput__report__free_unpacked(msg, NULL);
}



#if UNIT_TEST
void amp_test_report_results(uint64_t start_time, struct addrinfo *dest,
        struct opt_t *options) {
    report_results(start_time, dest, options);
}
#endif
