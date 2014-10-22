#ifndef _MEASURED_ASN_H
#define _MEASURED_ASN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "iptrie.h"


int connect_to_whois_server(void);
int amp_asn_flag_done(int fd);
int amp_asn_add_query(iptrie_node_t *root, void *data);
struct iptrie *amp_asn_fetch_results(int fd, struct iptrie *results);

#endif
