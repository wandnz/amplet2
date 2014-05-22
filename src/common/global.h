#ifndef _MEASURED_GLOBAL_H
#define _MEASURED_GLOBAL_H

#include <stdint.h>
#include <unbound.h>

typedef struct amp_ssl_opt {
    char *cacert;
    char *key;
    char *cert;
} amp_ssl_opt_t;

struct amp_global_t {
    char *ampname;
    char *collector;
    uint16_t port;
    char *testdir;
    char *interface;
    char *sourcev4;
    char *sourcev6;
    int vialocal;
    char *vhost;
    char *exchange;
    char *routingkey;
    int ssl;
    int fetch_remote;
    char *schedule_url;
    char *schedule_dir;
    char *nametable_dir;
    int fetch_freq;
    int control_enabled;
    char *control_port;
    char *control_interface;
    char *control_ipv4;
    char *control_ipv6;
    amp_ssl_opt_t amqp_ssl;
    amp_ssl_opt_t fetch_ssl;
    struct ub_ctx *ctx;
    char *nssock;
};

struct amp_global_t vars;
#endif
