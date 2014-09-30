#ifndef _TESTS_TRACEROUTE_AS_H
#define _TESTS_TRACEROUTE_AS_H

#include "traceroute.h"

typedef enum {
    AS_UNKNOWN = 0,
    AS_NULL = -1,
    AS_PRIVATE = -2,
} asn_t;

int set_as_numbers(struct dest_info_t *donelist);

#endif
