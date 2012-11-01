#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include <libwandevent.h>

#include "schedule.h"
#include "watchdog.h"
#include "test.h"



/*
 * Test function to investigate forking, rescheduling, setting maximum 
 * execution timers etc.
 */
static void fork_test(wand_event_handler_t *ev_hdl,test_schedule_item_t *test) {
    pid_t pid;

    if ( (pid = fork()) < 0 ) {
	perror("fork");
	return;
    } else if ( pid == 0 ) {
	/* child, prepare the environment and run the test functions */
	/* TODO prepare environment */
	/* TODO run pre test setup */
	/* TODO run test */
	execl("/bin/ping", "ping", "-c", "5", "localhost", NULL);
	perror("execl");
	exit(1);
    }

    /* schedule the watchdog to kill it if it takes too long */
    add_test_watchdog(ev_hdl, pid);
}



/*
 * TODO start forking a real program to test with: ls, ping? 
 */
void run_scheduled_test(struct wand_timer_t *timer) {
    schedule_item_t *item = (schedule_item_t *)timer->data;
    test_schedule_item_t *data;
    struct timeval next;

    assert(item->type == EVENT_RUN_TEST);

    data = (test_schedule_item_t *)item->data.test;
    
    printf("running a test at %d\n", (int)time(NULL));

    /* reschedule the test again */
    next = get_next_schedule_time(data->repeat, data->start, data->end, 
	    MS_FROM_TV(data->interval));
    timer->expire = wand_calc_expire(item->ev_hdl, next.tv_sec, next.tv_usec);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(item->ev_hdl, timer);

    fork_test(item->ev_hdl, data);
}
