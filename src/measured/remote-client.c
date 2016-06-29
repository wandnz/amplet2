#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/dh.h>

#include "debug.h"
#include "control.h"
#include "serverlib.h"
#include "ssl.h"
#include "measured.pb-c.h"
#include "controlmsg.h"
#include "modules.h"


struct option long_options[] = {
    {"cacert", required_argument, 0, '0'},
    {"cert", required_argument, 0, '9'},
    {"key", required_argument, 0, '8'},
    {"connect", required_argument, 0, 'c'},
    {"port", required_argument, 0, 'p'},
    {"test", required_argument, 0, 't'},
    {"list", required_argument, 0, 'l'},
    {"args", required_argument, 0, 'a'},
    {"debug", no_argument, 0, 'x'},
    {"help", no_argument, 0, 'h'},
};

static void usage(char *prog) {
    printf("usage: %s -c <host> -t <test> -- <target>\n", prog);
    printf("  --connect, -c <host>       host running amplet2-client to connect to\n");
    printf("  --port, -p    <port>       port to connect to (default %s)\n",
            DEFAULT_AMPLET_CONTROL_PORT);
    printf("  --test, -t    <test>       test to run\n");
    printf("  --list, -l                 list all available tests\n");
    printf("  --args, -a    <arg string> quoted string of test arguments\n");
    printf("  --cacert      <file>       PEM format CA certificate\n");
    printf("  --cert        <file>       PEM format certificate\n");
    printf("  --key         <file>       PEM format private key\n");
}



/*
 *
 */
static test_type_t test_from_name(char *name) {
    int i;

    for ( i = 0; i < AMP_TEST_LAST; i++ ) {
        if ( amp_tests[i] && amp_tests[i]->name ) {
            if ( strcmp(name, amp_tests[i]->name) == 0 ) {
                return i;
            }
        }
    }

    return AMP_TEST_INVALID;
}



static void list_all_tests(void) {
    int i;

    printf("Available tests (%s)\n", AMP_TEST_DIRECTORY);

    for ( i = 0; i < AMP_TEST_LAST; i++ ) {
        if ( amp_tests[i] && amp_tests[i]->name ) {
            printf("  %s\n", amp_tests[i]->name);
        }
    }
}



/*
 *
 */
int main(int argc, char *argv[]) {
    int len;
    void *buffer;
    int bytes;
    BIO *ctrl;
    amp_ssl_opt_t sslopts;
    struct addrinfo hints, *dest;
    amp_test_result_t result;
    Amplet2__Measured__Control msg = AMPLET2__MEASURED__CONTROL__INIT;
    Amplet2__Measured__Schedule schedule = AMPLET2__MEASURED__SCHEDULE__INIT;
    Amplet2__Measured__Control *response;

    int i;
    int opt;
    int option_index = 0;
    char *test_name = NULL;
    test_type_t test_type;
    char *host = "localhost";
    char *port = DEFAULT_AMPLET_CONTROL_PORT;
    char *args = NULL;
    amp_test_meta_t meta;
    int list = 0;

    memset(&meta, 0, sizeof(amp_test_meta_t));

    /* quieten down log messages while starting, we don't need to see them */
    log_level = LOG_WARNING;

    while ( (opt = getopt_long(argc, argv, "?h0:9:8:a:c:lp:t:x4:6:I:",
                    long_options, &option_index)) != -1 ) {
        switch ( opt ) {
            case '0': sslopts.cacert = optarg; break;
            case '9': sslopts.cert = optarg; break;
            case '8': sslopts.key = optarg; break;
            case 'a': args = optarg; break;
            case 'c': host = optarg; break;
            case 'l': list = 1; break;
            case 'p': port = optarg; break;
            case 't': test_name = optarg; break;
            case 'x': log_level = LOG_DEBUG; break;
            case '4': meta.sourcev4 = optarg; break;
            case '6': meta.sourcev6 = optarg; break;
            case 'I': meta.interface = optarg; break;
            case 'h':
            case '?':
            default: usage(argv[0]); exit(1);
        };
    }

    /* register tests after setting log_level, just in case it's useful */
    register_tests(AMP_TEST_DIRECTORY);

    if ( list ) {
        list_all_tests();
        return 1;
    }

    if ( test_name == NULL ) {
        usage(argv[0]);
        return 1;
    }

    if ( (test_type = test_from_name(test_name)) == AMP_TEST_INVALID ) {
        printf("Invalid test: %s\n", test_name);
        list_all_tests();
        return 1;
    }

    if ( initialise_ssl(&sslopts, NULL) < 0 ) {
        return -1;
    }

    if ( (ssl_ctx = initialise_ssl_context(&sslopts)) == NULL ) {
        return -1;
    }

    /* build test schedule item */
    schedule.has_test_type = 1;
    schedule.test_type = test_type;
    schedule.params = args;
    schedule.n_targets = argc - optind;
    schedule.targets = calloc(schedule.n_targets, sizeof(char*));
    for ( i = optind; i < argc; i++ ) {
        schedule.targets[i - optind] = argv[i];
    }

    msg.schedule = &schedule;
    msg.has_type = 1;
    msg.type = AMPLET2__MEASURED__CONTROL__TYPE__SCHEDULE;

    len = amplet2__measured__control__get_packed_size(&msg);
    buffer = malloc(len);
    amplet2__measured__control__pack(&msg, buffer);

    free(schedule.targets);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    getaddrinfo(host, port, &hints, &dest);

    /* connect to the control server, doing all the SSL establishment etc */
    if ( (ctrl = connect_control_server(dest, atoi(port), &meta)) == NULL ) {
        printf("failed to connect control server\n");
        return -1;
    }

    /* send the test and arguments to the server */
    if ( write_control_packet(ctrl, buffer, len) < 0 ) {
        printf("failed to write\n");
        return -1;
    }

    free(buffer);

    /* wait for the result */
    if ( (bytes = read_control_packet(ctrl, &buffer)) < 0 ) {
        printf("failed to read\n");
        return -1;
    }

    /*
     * This is a bit nasty, because we can get either a test level control
     * message with a result in it, or we can get a measured level control
     * message with an error in it. Try to unpack a measured level control
     * message and if that fails assume it actually has results...
     */
    response = amplet2__measured__control__unpack(NULL, bytes, buffer);
    if ( response && response->has_type ) {
        /* measured error - the remote end won't let us run the test */
        switch ( response->type ) {
            case AMPLET2__MEASURED__CONTROL__TYPE__ERROR:
                printf("error: %d\n", response->error->code);
                break;
            default:
                printf("unexpected message type\n");
                break;
        };
        amplet2__measured__control__free_unpacked(response, NULL);
    } else {
        /* not an error, assume it is a result and print it */
        result.data = buffer;
        result.len = bytes;

        /* print result using the test print functions, as if run locally */
        amp_tests[test_type]->print_callback(&result);
    }

    free(buffer);
    close_control_connection(ctrl);
    ssl_cleanup();

    freeaddrinfo(dest);
    unregister_tests();

    return 0;
}
