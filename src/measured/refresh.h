#ifndef _MEASURED_REFRESH_H
#define _MEASURED_REFRESH_H

#include <libwandevent.h>
#include <config.h>

/* number of seconds between checking file for changes */
#define FILE_CHECK_FREQ 60

/*
 * Data block for checking for file updates
 */
typedef struct watch_file_data {
#if HAVE_SYS_INOTIFY_H
    int fd;			    /* inotify file descriptor */
#else
    time_t last_update;		    /* time file was last changed */
#endif
    wand_event_handler_t *ev_hdl;   /* reference so we can reschedule */
} file_data_t;



#if HAVE_SYS_INOTIFY_H
void setup_file_refresh_inotify(wand_event_handler_t *ev_hdl, char *filename, 
	void *callback);
#else
void setup_file_refresh_timer(wand_event_handler_t *ev_hdl, char *filename, 
	void *callback);
#endif

#endif
