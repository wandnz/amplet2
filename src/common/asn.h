#ifndef _COMMON_ASN_H
#define _COMMON_ASN_H

#include "iptrie.h"

#define WHOIS_UNAVAILABLE -2

/* data block given to each resolving thread */
struct amp_asn_info {
    int fd;                     /* file descriptor to the test process */
    struct iptrie *trie;        /* shared ASN data (with the cache) */
    pthread_mutex_t *mutex;     /* protect the shared cache */
    time_t *refresh;            /* time the cache should be refreshed */
};

int connect_to_whois_server(void);
int amp_asn_flag_done(int fd);
int amp_asn_add_query(iptrie_node_t *root, void *data);
struct iptrie *amp_asn_fetch_results(int fd, struct iptrie *results);
void add_parsed_line(struct iptrie *result, char *line,
        struct amp_asn_info *info);
void process_buffer(struct iptrie *result, char *buffer, int buflen,
        int *offset, struct amp_asn_info *info, int *outstanding);
#endif
