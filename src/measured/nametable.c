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

#if HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

#include <libwandevent.h>
#include "schedule.h"
#include "nametable.h"


static name_entry_t *name_table = NULL;



/*
 * TODO do we want a magic name that forces a lookup rather than using a
 * static config file? So measured can do the lookup rather than making tests
 * do the name resolution themselves.
 */



/*
 * TODO: smarter data structure that will give faster lookups?
 */
static void insert_nametable_entry(char *name, struct addrinfo *info) {
    name_entry_t *entry;

    assert(name);
    assert(info);

    entry = (name_entry_t*)malloc(sizeof(name_entry_t));
    entry->name = strdup(name);
    entry->addr = info;

    /* until we try to be smarter, just add it to the front of the list */
    entry->next = name_table;
    name_table = entry;
}



/*
 *
 */
static void dump_nametable() {
    name_entry_t *tmp;
    char address[INET6_ADDRSTRLEN];
    printf("inet6 strlen = %d\n", INET6_ADDRSTRLEN);

    printf("NAMETABLE:\n");

    for ( tmp=name_table; tmp != NULL; tmp=tmp->next ) {
	assert(tmp);
	assert(tmp->addr);
	if ( tmp->addr->ai_addr->sa_family == AF_INET ) {
	    inet_ntop(AF_INET, 
		    &((struct sockaddr_in*)tmp->addr->ai_addr)->sin_addr, 
		    address, INET6_ADDRSTRLEN);

	} else if ( tmp->addr->ai_addr->sa_family == AF_INET6 ) {
	    inet_ntop(AF_INET6, 
		    &((struct sockaddr_in6*)tmp->addr->ai_addr)->sin6_addr,
		    address, INET6_ADDRSTRLEN);

	} else {
	    printf("unknown address family\n");
	    continue;
	}
	printf("%s %s\n", tmp->name, address);
    }
}


/*
 *
 */ 
static int compare_addrinfo(struct addrinfo *a, struct addrinfo *b) {
    assert(a);
    assert(b);
    assert(a->ai_addr);
    assert(b->ai_addr);

    if ( a->ai_addr->sa_family != b->ai_addr->sa_family )
	return 0;

    if ( a->ai_addr->sa_family == AF_INET ) {
	if ( ((struct sockaddr_in*)a->ai_addr)->sin_addr.s_addr == 
		((struct sockaddr_in*)b->ai_addr)->sin_addr.s_addr ) {
	    return 1;
	}

    } else if ( a->ai_addr->sa_family == AF_INET6 ) {
	if ( memcmp(((struct sockaddr_in6*)a->ai_addr)->sin6_addr.s6_addr,
		    ((struct sockaddr_in6*)b->ai_addr)->sin6_addr.s6_addr,
		    sizeof(struct in6_addr)) == 0 ) {
	    return 1;
	}
    }

    return 0;
}



/* 
 * TODO can we merge these functions so they aren't repeated for schedule
 * files as well as name tables?
 */

#if HAVE_SYS_INOTIFY_H
/*
 * inotify tells us the file has changed, so consume the event, clear the
 * existing nametable and load the new one.
 */
static void nametable_file_changed_event(struct wand_fdcb_t *evcb,
	__attribute__((unused)) enum wand_eventtype_t ev) {
    struct inotify_event buf;
    nametable_file_data_t *data = (nametable_file_data_t *)evcb->data;

    if ( read(data->fd, &buf, sizeof(buf)) == sizeof(buf) ) {
	if ( buf.mask & IN_MODIFY ) {
	    /* XXX TODO should this invalidate tests? depends how dests work */
	    clear_nametable();
	    read_nametable_file();
	}
    }
}



/* 
 * set up inotify to monitor the nametable file for changes 
 */
static void setup_nametable_refresh_inotify(wand_event_handler_t *ev_hdl) {
    int inotify_fd;
    int nametable_wd;
    struct wand_fdcb_t *nametable_watch_ev;
    nametable_file_data_t *nametable_data;
    
    nametable_watch_ev = 
	(struct wand_fdcb_t*)malloc(sizeof(struct wand_fdcb_t));
    nametable_data = 
	(nametable_file_data_t*)malloc(sizeof(nametable_file_data_t));
    
    if ( (inotify_fd = inotify_init()) < 0 ) {
	perror("inotify_init");
	exit(1);
    }

    if ( (nametable_wd = 
		inotify_add_watch(inotify_fd, NAMETABLE_FILE, IN_MODIFY)) < 0 ){
	perror("inotify_add_watch");
	exit(1);
    }

    /* save inotify_fd so we can read from it later */
    nametable_data->fd = inotify_fd;
    nametable_data->ev_hdl = ev_hdl;
    /* nametable event on the inotify_fd being available for reading */
    nametable_watch_ev->data = nametable_data;
    nametable_watch_ev->fd = inotify_fd;
    nametable_watch_ev->flags = EV_READ;
    nametable_watch_ev->callback = nametable_file_changed_event;
    wand_add_event(ev_hdl, nametable_watch_ev);
}

#else

/*
 * Check if the nametable file has been modified since the last check. If it
 * has then this invalidates all currently scheduled tests (which will need to
 * be cleared). The file needs to be read and the new tests added to the
 * schedule.
 *
 * TODO do we care about the file changing multiple times a second?
 */
static void check_nametable_file(struct wand_timer_t *timer) {
    nametable_file_data_t *data = (nametable_file_data_t *)timer->data;
    struct stat statInfo;
    time_t now;
    
    /* check if the nametable file has changed since last time */
    now = time(NULL);
    if ( stat(NAMETABLE_FILE, &statInfo) != 0 ) {
	perror("error statting nametable file");
	exit(1);
    }

    if ( statInfo.st_mtime > data->last_update ) {
	/* clear out all events and add new ones */
	fprintf(stderr, "nametable file modified, updating\n");
	/* XXX TODO should this invalidate tests? depends how dests work */
	clear_nametable();
	read_nametable_file();
	data->last_update = statInfo.st_mtime;
	fprintf(stderr, "Done updating nametable file\n");
    }
    
    /* reschedule the check again */
    timer->expire = wand_calc_expire(data->ev_hdl, NAMETABLE_CHECK_FREQ, 0);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(data->ev_hdl, timer);
}



/* 
 * set up a libwandevent timer to monitor the nametable file for changes 
 */
static void setup_nametable_refresh_timer(wand_event_handler_t *ev_hdl) {
    struct wand_timer_t *nametable_timer;
    nametable_file_data_t *nametable_data;

    nametable_timer = (struct wand_timer_t*)malloc(sizeof(struct wand_timer_t));
    nametable_data = 
	(nametable_file_data_t*)malloc(sizeof(nametable_file_data_t));

    /* record now as the time it was last updated */
    nametable_data->last_update = time(NULL);
    nametable_data->ev_hdl = ev_hdl;
    /* schedule another read of the file in 60 seconds */
    nametable_timer->expire = wand_calc_expire(ev_hdl, NAMETABLE_CHECK_FREQ, 0);
    nametable_timer->callback = check_nametable_file;
    nametable_timer->data = nametable_data;
    nametable_timer->prev = NULL;
    nametable_timer->next = NULL;
    wand_add_timer(ev_hdl, nametable_timer);
}

#endif


/*
 *
 */
void setup_nametable_refresh(wand_event_handler_t *ev_hdl) {
#if HAVE_SYS_INOTIFY_H
    /* use inotify if we are on linux, it is nicer and quicker */
    setup_nametable_refresh_inotify(ev_hdl);
#else
    /* if missing inotify then use libwandevent timers to check regularly */
    setup_nametable_refresh_timer(ev_hdl);
#endif
}



/*
 * 
 */
void clear_nametable() {
    name_entry_t *tmp;
     
    while ( name_table != NULL ) {
	tmp = name_table;
	name_table = name_table->next;
	free(tmp->name);
	freeaddrinfo(tmp->addr);
	free(tmp);
    }

    //name_table = NULL;
}



/*
 *
 */
struct addrinfo *name_to_address(char *name) {
    name_entry_t *tmp;

    assert(name);

    if ( name_table == NULL ) {
	return NULL;
    }

    for ( tmp=name_table; tmp != NULL; tmp=tmp->next ) {
	if ( strcmp(name, tmp->name) == 0 ) {
	    return tmp->addr;
	}
    }

    return NULL;
}



/*
 * Return the whole structure or just the name? What format input?
 */
char *address_to_name(struct addrinfo *address) {
    name_entry_t *tmp;

    assert(address);

    if ( name_table == NULL ) {
	return NULL;
    }

    for ( tmp=name_table; tmp != NULL; tmp=tmp->next ) {
	/* work down into struct and compare based on family */
	if ( compare_addrinfo(address, tmp->addr) ) {
	    return tmp->name;
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
    int foo;

    if ( (in = fopen(NAMETABLE_FILE, "r")) == NULL ) {
	perror("error opening nametable file");
	exit(1);
    }

    while ( fgets(line, sizeof(line), in) != NULL ) {
	char *name, *address;

	/* ignore comments and blank lines */
	if ( line[0] == '#'  || line[0] == '\n' ) {
	    continue;
	}
	printf("line=%s", line);

	/* read name address */
	if ( (name = strtok(line, NAMETABLE_DELIMITER)) == NULL )
	    continue;
	if ( (address = strtok(NULL, NAMETABLE_DELIMITER)) == NULL )
	    continue;

	printf("name:%s address:%s\n", name, address);
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_flags = AI_NUMERICHOST;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = 0;
	hint.ai_protocol = 0;
	hint.ai_addrlen = 0;
	hint.ai_addr = NULL;
	hint.ai_canonname = NULL;
	hint.ai_next = NULL;
	addrinfo = NULL;
	if ( (foo = getaddrinfo(address, NULL, &hint, &addrinfo)) != 0 ) {
	    /* TODO log error */
	    continue;
	}
	printf("foo:%d\n", addrinfo->ai_addrlen);
	insert_nametable_entry(name, addrinfo);
    }

    fclose(in);

    dump_nametable();
}

