#ifndef _COMMON_AMPRESOLV_H
#define _COMMON_AMPRESOLV_H

#include <unbound.h>

struct amp_resolve_data {
    int max;
    int outstanding;
    struct addrinfo **addrlist;
};

struct ub_ctx *amp_resolve_init(char *servers[], int nscount, char *sourcev4,
        char *sourcev6);
void amp_resolve_add(struct ub_ctx *ctx, struct addrinfo **res, char *name,
        int family, int max);
void amp_resolve_wait(struct ub_ctx *ctx);
void amp_resolve_freeaddr(struct addrinfo *addrlist);


#endif
