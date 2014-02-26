#ifndef _MEASURED_GLOBAL_H
#define _MEASURED_GLOBAL_H

#include <stdint.h>

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
    char *exchange;
    char *routingkey;
    int ssl;
    char *cacert;
    char *key;
    char *cert;
    int fetch_remote;
    char *schedule_url;
    int control_enabled;
    char *control_port;
    char *control_address;
    amp_ssl_opt_t fetch_ssl;
    /* TODO make a collector ssl struct too */
    // amp_ssl_t collector_ssl;
};

struct amp_global_t vars;
#endif
