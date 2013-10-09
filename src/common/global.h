#ifndef _MEASURED_GLOBAL_H
#define _MEASURED_GLOBAL_H

#include <stdint.h>

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
};

struct amp_global_t vars;
#endif
