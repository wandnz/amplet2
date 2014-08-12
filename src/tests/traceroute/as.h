#ifndef _TESTS_TRACEROUTE_AS_H
#define _TESTS_TRACEROUTE_AS_H

#include "traceroute.h"

#define INET_AS_MAP_ZONE "origin.asn.cymru.com"
#define INET6_AS_MAP_ZONE "origin6.asn.cymru.com"

typedef enum {
    AS_UNKNOWN = 0,
    AS_NULL = -1,
    AS_PRIVATE = -2,
} asn_t;

int set_as_numbers(struct stopset_t *stopset, struct dest_info_t *donelist);

#endif
