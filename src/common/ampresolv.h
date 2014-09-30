#ifndef _COMMON_AMPRESOLV_H
#define _COMMON_AMPRESOLV_H

#include <stdint.h>
#include <pthread.h>
#include <unbound.h>

#define MAX_DNS_NAME_LEN 256

/* max wait between checking if all DNS responses have come in: 10ms */
#define MAX_DNS_POLL_USEC 10000

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

/* data block for callback function when name resolution is complete */
struct amp_resolve_data {
    pthread_mutex_t *lock;
    int max;                    /* maximum number of results to return */
    int qcount;                 /* how many requests for name, shared max */
    int *remaining;             /* total requests for test, shared addrlist */
    struct addrinfo **addrlist; /* list to store the results in */
};

/* data block used to transfer information about a query to be performed */
struct amp_resolve_query {
    uint8_t namelen;            /* length of the name string that follows */
    uint8_t count;              /* maximum number of results to return */
    uint8_t family;             /* address family to query for or AF_UNSPEC */
};

/*
 * XXX may need to rethink this, can it be reconciled with the name table
 * entry? or are they too different?
 */
struct resolve_dest {
    char *name;                 /* name to be resolved */
    struct addrinfo *addr;      /* temp store for the result of getaddrinfo */
    uint8_t count;              /* maximum count of resolved addresses to use */
    int family;                 /* family of addresses to resolve */
    struct resolve_dest *next;
};
typedef struct resolve_dest resolve_dest_t;

struct ub_ctx *amp_resolver_context_init(char *servers[], int nscount,
        char *sourcev4, char *sourcev6);
void amp_resolve_add(struct ub_ctx *ctx, struct addrinfo **res,
        pthread_mutex_t *addrlist_lock, char *name, int family, int max,
        int *remaining);
void amp_resolve_wait(struct ub_ctx *ctx, pthread_mutex_t *lock,
        int *remaining);
void amp_resolve_freeaddr(struct addrinfo *addrlist);
void amp_resolver_context_delete(struct ub_ctx *ctx);

struct addrinfo *amp_resolve_get_list(int fd);
int amp_resolve_add_new(int fd, resolve_dest_t *resolve);
int amp_resolve_flag_done(int fd);
int amp_resolver_connect(char *path);
#endif
