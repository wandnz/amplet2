#include <config.h>
#include <malloc.h>
#include <stdlib.h>
#include <libwandevent.h>

#if HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

#include "refresh.h"
#include "debug.h"


#if HAVE_SYS_INOTIFY_H
/* 
 * set up inotify to monitor a file for changes 
 */
void setup_file_refresh_inotify(wand_event_handler_t *ev_hdl, 
	char *filename, void *callback) {

    int inotify_fd;
    int file_wd;
    struct wand_fdcb_t *file_watch_ev;
    file_data_t *file_data;
    
    Log(LOG_DEBUG, "Using inotify to monitor file %s", filename);
    
    file_watch_ev = (struct wand_fdcb_t*)malloc(sizeof(struct wand_fdcb_t));
    file_data = (file_data_t*)malloc(sizeof(file_data_t));
    
    if ( (inotify_fd = inotify_init()) < 0 ) {
	perror("inotify_init");
	exit(1);
    }

    /*
     * FIXME watching for IN_MODIFY works in the general case, but editors
     * like vim do unusual things like working on a temporary file then moving
     * it over top of the actual file which doesn't trigger a modify event.
     * The correct way to do this appears to be to watch the whole config
     * directory and filter events based on the files involved.
     */
    if ( (file_wd = inotify_add_watch(inotify_fd, filename, IN_MODIFY)) < 0 ) {
	perror("inotify_add_watch");
	exit(1);
    }

    /* save inotify_fd so we can read from it later */
    file_data->fd = inotify_fd;
    file_data->ev_hdl = ev_hdl;
    /* event on the inotify_fd being available for reading */
    file_watch_ev->data = file_data;
    file_watch_ev->fd = inotify_fd;
    file_watch_ev->flags = EV_READ;
    file_watch_ev->callback = callback;
    wand_add_event(ev_hdl, file_watch_ev);
}

#else

/* 
 * set up a libwandevent timer to monitor a file for changes 
 */
void setup_file_refresh_timer(wand_event_handler_t *ev_hdl,
	char *filename, void *callback) {

    struct wand_timer_t *file_timer;
    file_data_t *file_data;
    
    Log(LOG_DEBUG, "Using polling to monitor file %s (interval: %ds)", 
	    filename, FILE_CHECK_FREQ);

    file_timer = (struct wand_timer_t*)malloc(sizeof(struct wand_timer_t));
    file_data = (file_data_t*)malloc(sizeof(file_data_t));

    /* record now as the time it was last updated */
    file_data->last_update = time(NULL);
    file_data->ev_hdl = ev_hdl;
    /* schedule another read of the file in 60 seconds */
    file_timer->expire = wand_calc_expire(ev_hdl, FILE_CHECK_FREQ, 0);
    file_timer->callback = callback;
    file_timer->data = file_data;
    file_timer->prev = NULL;
    file_timer->next = NULL;
    wand_add_timer(ev_hdl, file_timer);
}

#endif
