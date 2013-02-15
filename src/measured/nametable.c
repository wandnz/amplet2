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

#if HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

#include <libwandevent.h>
#include "schedule.h"
#include "nametable.h"
#include "debug.h"
#include "refresh.h"


static struct addrinfo *name_table = NULL;


/*
 * TODO do we need some sort of NONE target like the existing AMP uses? Tests
 * to URLs etc often use NONE with the URL as a parameter.
 */



/*
 * TODO: smarter data structure that will give faster lookups?
 */
static void insert_nametable_entry(char *name, struct addrinfo *info) {
    assert(name);
    assert(info);
    assert(info->ai_next == NULL);

    info->ai_canonname = strdup(name);
    info->ai_next = name_table;
    name_table = info;
}



/*
 *
 */
static void dump_nametable() {
    struct addrinfo *tmp;
    char address[INET6_ADDRSTRLEN];

    Log(LOG_DEBUG, "====== NAMETABLE ======");

    for ( tmp=name_table; tmp != NULL; tmp=tmp->ai_next ) {
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



#if HAVE_SYS_INOTIFY_H
/*
 * inotify tells us the file has changed, so consume the event, clear the
 * existing nametable and load the new one.
 */
static void nametable_file_changed_event(struct wand_fdcb_t *evcb,
	__attribute__((unused)) enum wand_eventtype_t ev) {
    struct inotify_event buf;
    file_data_t *data = (file_data_t *)evcb->data;

    if ( read(data->fd, &buf, sizeof(buf)) == sizeof(buf) ) {
	if ( buf.mask & IN_MODIFY ) {
	    /* 
	     * schedule relies on the names, so clear them out, load all the
	     * new names and then reload the schedule.
	     */
	    clear_test_schedule(data->ev_hdl);
	    clear_nametable();
	    read_nametable_file();
	    read_schedule_file(data->ev_hdl);
	}
    }
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
    file_data_t *data = (file_data_t *)timer->data;
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
	Log(LOG_INFO, "Nametable file modified, updating\n");
	/* 
	 * schedule relies on the names, so clear them out, load all the
	 * new names and then reload the schedule.
	 */
	clear_test_schedule(data->ev_hdl);
	clear_nametable();
	read_nametable_file();
	read_schedule_file(data->ev_hdl);
	data->last_update = statInfo.st_mtime;
	Log(LOG_INFO, "Done updating nametable file\n");
    }
    
    /* reschedule the check again */
    timer->expire = wand_calc_expire(data->ev_hdl, FILE_CHECK_FREQ, 0);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(data->ev_hdl, timer);
}

#endif



/*
 *
 */
void setup_nametable_refresh(wand_event_handler_t *ev_hdl) {
#if HAVE_SYS_INOTIFY_H
    /* use inotify if we are on linux, it is nicer and quicker */
    setup_file_refresh_inotify(ev_hdl, NAMETABLE_FILE, 
	    nametable_file_changed_event);
#else
    /* if missing inotify then use libwandevent timers to check regularly */
    setup_file_refresh_timer(ev_hdl, NAMETABLE_FILE, check_nametable_file);
#endif
}



/*
 * 
 */
void clear_nametable() {
    if ( name_table != NULL ) {
	freeaddrinfo(name_table);
	name_table = NULL;
    }
}



/*
 *
 */
struct addrinfo *name_to_address(char *name) {
    struct addrinfo *tmp;

    assert(name);

    if ( name_table == NULL ) {
	return NULL;
    }

    for ( tmp=name_table; tmp != NULL; tmp=tmp->ai_next ) {
	if ( strcmp(name, tmp->ai_canonname) == 0 ) {
	    return tmp;
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
	Log(LOG_ALERT, "Failed to open nametable file: %s\n", strerror(errno));
	exit(1);
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

	if ( name_to_address(name) != NULL ) {
	    Log(LOG_WARNING, 
		    "Duplicate entry in name table for destination '%s'\n",
		    name);
	    continue;
	}

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

