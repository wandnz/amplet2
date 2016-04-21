#ifndef _COMMON_DSCP_H
#define _COMMON_DSCP_H

#include <stdint.h>

char *dscp_to_str(const uint8_t value);
int parse_dscp_value(const char *value, uint8_t *result);

#endif
