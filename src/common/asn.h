#ifndef _MEASURED_ASN_H
#define _MEASURED_ASN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int amp_asn_flag_done(int fd);
int amp_asn_connect(char *path);
int amp_asn_add_query(int fd, struct sockaddr *address);
struct addrinfo *amp_asn_get_list(int fd);

#endif
