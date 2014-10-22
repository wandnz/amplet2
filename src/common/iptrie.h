#ifndef _COMMON_IPTRIE_H
#define _COMMON_IPTRIE_H

#include <stdint.h>
#include <netinet/in.h>


#define iptrie_node_t struct iptrie_node
struct iptrie_node {
    /* ASNs are only 32bit, but we can use the extra space as markers */
    int64_t as;
    uint8_t prefix;
    struct sockaddr *address;

    iptrie_node_t *left;
    iptrie_node_t *right;
};

struct iptrie {
    iptrie_node_t *ipv4;
    iptrie_node_t *ipv6;
};


void iptrie_add(struct iptrie *root, struct sockaddr *address,
        uint8_t prefix, int64_t as);
int64_t iptrie_lookup_as(struct iptrie *root, struct sockaddr *address);
void iptrie_clear(struct iptrie *root);
int iptrie_on_all_leaves(struct iptrie *root,
        int (*func)(iptrie_node_t*, void*), void *data);

#endif
