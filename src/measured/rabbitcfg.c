#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include "rabbitcfg.h"
#include "debug.h"



/*
 * We fork and call rabbitmqctl a few times to configure parts of the local
 * rabbitmq broker.
 */
static int run_rabbitmqctl(char *args[]) {
    int pid;
    int status;

    if ( (pid = fork()) < 0 ) {
    	Log(LOG_ALERT, "Failed to fork: %s", strerror(errno));
	return -1;
    } else if ( pid == 0 ) {
        int out = STDOUT_FILENO;
        int err = STDERR_FILENO;
        int tty = isatty(fileno(stdout));

        /*
         * Close stdout and stderr so we don't see rabbitmqctl messages (unless
         * running in debug mode). The "-q" flag to rabbitmqctl doesn't make
         * it quiet enough.
         */
        if ( tty && log_level != LOG_DEBUG ) {
            out = dup(STDOUT_FILENO);
            err = dup(STDERR_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
        }

        if ( execv(RABBITMQCTL, args) < 0 ) {
            /* restore stdout/stderr if we need to print an error */
            if ( tty && log_level != LOG_DEBUG ) {
                dup2(out, STDOUT_FILENO);
                dup2(err, STDERR_FILENO);
            }
            Log(LOG_ALERT, "Failed to run %s:%s", RABBITMQCTL, strerror(errno));
            exit(-1);
        }
        exit(0);
    }

    waitpid(pid, &status, 0);

    if ( WIFEXITED(status) ) {
        /* rabbitmqctl returns 1 when not run as root, make it a major error */
        if ( WEXITSTATUS(status) == 1 ) {
            Log(LOG_ALERT, "Insufficient permissions (are you root?)");
            return -1;
        }
        return WEXITSTATUS(status);
    }

    return -1;
}



/*
 * Create a new vhost on the local rabbitmq server so that all the queues
 * etc for this client are in a self-contained space, not requiring access
 * to other vhosts.
 */
static int create_rabbitmq_vhost(char *username) {
    char *args[] = { RABBITMQCTL, "add_vhost", username, NULL };

    Log(LOG_DEBUG, "Creating rabbitmq vhost \"%s\"", username);

    return run_rabbitmqctl(args);
}



/*
 * Create a new local rabbitmq user that will only have permissions on it's own
 * particular vhost.
 */
static int create_rabbitmq_user(char *username) {
    char *args[] = { RABBITMQCTL, "add_user", username, username, NULL };

    Log(LOG_DEBUG, "Creating rabbitmq user \"%s\"", username);

    return run_rabbitmqctl(args);
}



/*
 * Grant the new local rabbitmq user permissions on its vhost.
 */
static int grant_rabbitmq_permissions(char *username) {
    char *args[] = { RABBITMQCTL, "set_permissions",
        "-p", username, /* vhost */
        username,       /* username */
        ".*",           /* conf */
        ".*",           /* read */
        ".*",           /* write */
        NULL
    };

    Log(LOG_DEBUG, "Granting permissions on vhost \"%s\" to user \"%s\"",
            username, username);

    return run_rabbitmqctl(args);
}



/*
 * Create the vhost, user and configure permissions for reporting data to
 * the local rabbitmq collector.
 */
int setup_rabbitmq_user(char *username) {
    assert(username);

    if ( create_rabbitmq_vhost(username) < 0 ) {
        Log(LOG_ALERT, "Failed to create rabbitmq vhost for amplet2 client %s",
                username);
        return -1;
    }

    if ( create_rabbitmq_user(username) < 0 ) {
        Log(LOG_ALERT, "Failed to create rabbitmq user for amplet2 client %s",
                username);
        return -1;
    }

    if ( grant_rabbitmq_permissions(username) < 0 ) {
        Log(LOG_ALERT,
                "Failed to grant rabbitmq permissions for amplet2 client %s",
                username);
        return -1;
    }

    return 0;
}



/*
 * Create a shovel that moves data from the local queue to the remote
 * collection server. The shovel should authenticate at the remote end using
 * external SSL auth.
 *
 * The shovel is also responsible for creating the local queues that we use
 * to report our data into - by default it will create our queues as durable
 * with no other arguments.
 */
int setup_rabbitmq_shovel(char *ampname, char *local, char *collector, int port,
        char *cacert, char *cert, char *key, char *exchange, char *routingkey) {

    char *args[] = { RABBITMQCTL, "set_parameter", "shovel", ampname,
        NULL, NULL };
    int result;

    Log(LOG_DEBUG, "Creating rabbitmq shovel for \"%s\" to %s",
            ampname, collector);

    assert(ampname);
    assert(local);
    assert(collector);
    assert(port > 0);
    assert(cacert);
    assert(cert);
    assert(key);
    assert(exchange);
    assert(routingkey);

    /*
     * Create the shovel configuration to send data from our queues in our
     * own vhost back to the collector server.
     */
    if ( asprintf(&args[4],
                "{\"src-uri\":\"amqp://%s:%s@%s/%s\", "
                "\"src-queue\":\"report\", "
                "\"dest-uri\":\"amqps://%s:%d"
                "?cacertfile=%s"
                "&certfile=%s"
                "&keyfile=%s"
                "&verify=verify_peer"
                "&fail_if_no_peer_cert=true"
                "&auth_mechanism=external\", "
                "\"dest-exchange\":\"%s\", "
                "\"dest-exchange-key\":\"%s\"}",
                ampname, ampname, local, ampname, collector, port, cacert,
                cert, key, exchange, routingkey) < 0 ) {
        exit(-1);
    }

    result = run_rabbitmqctl(args);
    free(args[4]);

    return result;
}
