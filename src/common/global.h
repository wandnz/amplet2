#ifndef _MEASURED_GLOBAL_H
#define _MEASURED_GLOBAL_H

#include <stdint.h>
#include <unbound.h>

#include "ssl.h"

struct amp_global_t {
    char *ampname;
    char *collector;
    uint16_t port;
    int vialocal;
    char *local;
    char *vhost;
    char *exchange;
    char *routingkey;
    int ssl;
    int control_port;
    amp_ssl_opt_t amqp_ssl;
    struct ub_ctx *ctx;
    char *asnsock;
    char *nssock;
    int nssock_fd;
    int asnsock_fd;
    char **argv;
    int argc;
};

struct amp_global_t vars;
#endif
