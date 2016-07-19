#ifndef _COMMON_ICMPCODE_H
#define _COMMON_ICMPCODE_H

#include <stdint.h>

char *icmp_code_str(uint8_t family, uint8_t type, uint8_t code);

#endif
