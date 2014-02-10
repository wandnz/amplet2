#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <libwandevent.h>
#include "schedule.h"
#include "nametable.h"
#include "debug.h"


static nametable_t *name_table = NULL;


/*
 * TODO do we need some sort of NONE target like the existing AMP uses? Tests
 * to URLs etc often use NONE with the URL as a parameter.
 */



/*
 * Insert a new nametable entry on to the front of the list and set the
 * canonical name to the name we use for it.
 */
static void insert_nametable_entry(char *name, struct addrinfo *info) {
    nametable_t *item;
    assert(name);
    assert(info);
    assert(info->ai_next == NULL);

    info->ai_canonname = strdup(name);

    if ( (item = name_to_address(name)) == NULL ) {
        /* if it doesn't exist, create it with the single struct addrinfo */
        item = (nametable_t *)malloc(sizeof(nametable_t));
        item->addr = info;
        item->next = NULL;
        item->count = 1;
        name_table = item;
    } else {
        /* if it does exist, add this struct addrinfo to the list */
        info->ai_next = item->addr;
        item->addr = info;
        item->count++;
    }
}



/*
 * Dump the entire contents of the nametable for debugging.
 */
static void dump_nametable(void) {
    struct addrinfo *tmp;
    nametable_t *item;
    char address[INET6_ADDRSTRLEN];

    Log(LOG_DEBUG, "====== NAMETABLE ======");

    for ( item=name_table; item != NULL; item=item->next ) {
        for ( tmp=item->addr; tmp != NULL; tmp=tmp->ai_next ) {
            assert(tmp);
            assert(tmp->ai_addr);
            assert(tmp->ai_canonname);
            if ( tmp->ai_addr->sa_family == AF_INET ) {
                inet_ntop(AF_INET,
                        &((struct sockaddr_in*)tmp->ai_addr)->sin_addr,
                        address, INET6_ADDRSTRLEN);

            } else if ( tmp->ai_addr->sa_family == AF_INET6 ) {
                inet_ntop(AF_INET6,
                        &((struct sockaddr_in6*)tmp->ai_addr)->sin6_addr,
                        address, INET6_ADDRSTRLEN);

            } else {
                Log(LOG_WARNING, "unknown address family: %d\n",
                        tmp->ai_addr->sa_family);
                continue;
            }
            Log(LOG_DEBUG, "%s %s\n", tmp->ai_canonname, address);
        }
    }
}



/*
 * Empty the nametable. It's a list of addrinfo structs, so freeaddrinfo()
 * will do all the hard work.
 */
void clear_nametable() {
    nametable_t *item;
    nametable_t *tmp;

    if ( name_table != NULL ) {
        for ( item=name_table; item != NULL; /* increment in body */ ) {
            /* free addresses for current item */
            if ( item->addr != NULL ) {
                freeaddrinfo(item->addr);
            }

            /* free current item */
            tmp = item;
            item = item->next;
            free(tmp);
        }
	name_table = NULL;
    }
}



/*
 * Traverse the list and return the first address structure that has the
 * given name.
 */
nametable_t *name_to_address(char *name) {
    nametable_t *item;

    assert(name);

    if ( name_table == NULL ) {
	return NULL;
    }

    for ( item=name_table; item != NULL; item=item->next ) {
        assert(item->addr);
        assert(item->addr->ai_canonname);
        if ( strcmp(name, item->addr->ai_canonname) == 0 ) {
            return item;
        }
    }

    return NULL;
}



/*
 *
 */
void read_nametable_file() {
    FILE *in;
    char line[MAX_NAMETABLE_LINE];
    struct addrinfo hint;
    struct addrinfo *addrinfo;
    int res;

    Log(LOG_INFO, "Loading nametable from %s", NAMETABLE_FILE);

    if ( (in = fopen(NAMETABLE_FILE, "r")) == NULL ) {
	Log(LOG_WARNING, "Skipping nametable file: %s\n", strerror(errno));
	return;
    }

    while ( fgets(line, sizeof(line), in) != NULL ) {
	char *name, *address;

	/* ignore comments and blank lines */
	if ( line[0] == '#'  || line[0] == '\n' ) {
	    continue;
	}
	Log(LOG_DEBUG, "line=%s", line);

	/* read name address */
	if ( (name = strtok(line, NAMETABLE_DELIMITER)) == NULL )
	    continue;
	if ( (address = strtok(NULL, NAMETABLE_DELIMITER)) == NULL )
	    continue;

	Log(LOG_DEBUG, "Loaded name:%s address:%s\n", name, address);
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_flags = AI_NUMERICHOST;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM; /* limit it to a single socket type */
	hint.ai_protocol = 0;
	hint.ai_addrlen = 0;
	hint.ai_addr = NULL;
	hint.ai_canonname = NULL;
	hint.ai_next = NULL;
	addrinfo = NULL;
	if ( (res = getaddrinfo(address, NULL, &hint, &addrinfo)) != 0 ) {
	    Log(LOG_WARNING, "Failed to load address info for %s (%s)",
		    name, address);
	    continue;
	}
	insert_nametable_entry(name, addrinfo);
    }

    fclose(in);

    dump_nametable();
}

