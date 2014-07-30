#ifndef _TESTS_TRACEROUTE_AS_H
#define _TESTS_TRACEROUTE_AS_H

#include "traceroute.h"

#define INET_AS_MAP_ZONE "origin.asn.cymru.com"
#define INET6_AS_MAP_ZONE "origin6.asn.cymru.com"

int set_as_numbers(struct stopset_t *stopset, struct dest_info_t *donelist);

#endif
