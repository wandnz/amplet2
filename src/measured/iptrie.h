#ifndef _MEASURED_IPTRIE_H
#define _MEASURED_IPTRIE_H

#include <stdint.h>
#include <netinet/in.h>


#define iptrie_t struct iptrie
struct iptrie {
    uint32_t as;
    uint8_t prefix;
    struct sockaddr *address;

    iptrie_t *left;
    iptrie_t *right;
};

iptrie_t *iptrie_add(iptrie_t *root, struct sockaddr *address, uint8_t prefix,
        uint32_t as);
uint32_t iptrie_lookup_as(iptrie_t *root, struct sockaddr *address);
void iptrie_clear(iptrie_t *root);

#endif
