#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "schedule.h"
#include "watchdog.h"


/* 
 * list of information about running tests that can be used to tidy up the
 * watchdog timers once they complete
 */
struct running_test_t *running = NULL;



/*
 * Add a watchdog timer that will kill a test should it run too long.
 * TODO should different tests be able to run for different durations?
 */
void add_test_watchdog(wand_event_handler_t *ev_hdl, pid_t pid) {
    struct running_test_t *info;
    struct wand_timer_t *timer;
    schedule_item_t *item;
    kill_schedule_item_t *kill;

    /* store information about the test so we can kill it later */
    kill = (kill_schedule_item_t *)malloc(sizeof(kill_schedule_item_t));
    kill->pid = pid;
    item = (schedule_item_t *)malloc(sizeof(schedule_item_t));
    item->type = EVENT_CANCEL_TEST;
    item->ev_hdl = ev_hdl;
    item->data.kill = kill;
	
    /* schedule task to kill test process if it goes too long */
    timer = (struct wand_timer_t *)malloc(sizeof(struct wand_timer_t));
    timer->data = item;
    timer->expire = wand_calc_expire(ev_hdl, 3, 0);
    timer->callback = kill_running_test;
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(ev_hdl, timer);


    /* add the running test information to the active list */
    info = (struct running_test_t *)malloc(sizeof(struct running_test_t));
    info->pid = pid;
    info->timer = timer;
    info->ev_hdl = ev_hdl;
    
    /* just stick it on the front of the list for now */
    info->next = running;
    info->prev = NULL;
    if ( running != NULL )
	running->prev = info;
    running = info;
}


/* 
 * TODO need a reference to the event handler to search all events! 
 * Also, if the event has triggered it is no longer in this list (but this 
 * function still gets called (but that can be prevented by checking 
 * WIFEXITED vs WIFSIGNALED).
 */
#if 0
static void cancel_test_watchdog2(pid_t pid) {

}
#endif


/*
 * If a test completes for any reason then remove the associated kill task.
 *
 * TODO better to maintain running info, or search all timers in libwandevent
 * like we do to clear all events?
 *
 * TODO if a test ends properly, how do we remove the timer? We have the pid
 * and that's it - do we want to search all events to find the cancel one?
 */
static void cancel_test_watchdog(pid_t pid) {
    struct running_test_t *tmp = running;

    /* find the running info for this particular test */
    while ( tmp != NULL ) {
	if ( tmp->pid == pid ) {

	    /* if the timer hasn't fired, remove it so it won't */
	    if ( tmp->timer->prev != (void*)0xdeadbeef ) {
		wand_del_timer(tmp->ev_hdl, tmp->timer);
	    }

	    /* free all the data associated with the watchdog */
	    if ( tmp->timer->data != NULL ) {
		schedule_item_t *item = (schedule_item_t *)tmp->timer->data;
		assert(item->type == EVENT_CANCEL_TEST);
		assert(item->data.kill);
		free(item->data.kill);
		free(item);
	    }
	    free(tmp->timer);

	    /* update list of running tests */
	    if ( tmp->prev != NULL ) {
		tmp->prev->next = tmp->next;
	    } else {
		running = tmp->next;
	    }

	    if ( tmp->next != NULL ) {
		tmp->next->prev = tmp->prev;
	    }
	    free(tmp);
	    return;
	}
	tmp = tmp->next;
    }
    assert(0);
}



/*
 * Test using SIGCHLD to know when and which children have completed so that
 * their scheduled timeout task can be removed from the list.
 */
void child_reaper(__attribute__((unused))struct wand_signal_t *signal) {
    siginfo_t infop;
    infop.si_pid = 0;

    waitid(P_ALL, 0, &infop, WNOHANG | WEXITED);
    printf("CHILD terminated, pid: %d\n", infop.si_pid);

    /* find in the list of events and remove the scheduled kill */
    assert(infop.si_pid > 0);
    cancel_test_watchdog(infop.si_pid);
}



/*
 * Kill a test process that has run for too long. The SIGCHLD handler will 
 * take care of tidying everything up.
 */
void kill_running_test(struct wand_timer_t *timer) {
    schedule_item_t *item = (schedule_item_t *)timer->data;
    kill_schedule_item_t *data;

    assert(item->type == EVENT_CANCEL_TEST);

    data = (kill_schedule_item_t *)item->data.kill;

    assert(data->pid > 0);

    /* TODO send SIGINT first like amp1 did? killpg() vs kill() */
    /* kill the test */
    if ( kill(data->pid, SIGKILL) < 0 ) {
	perror("kill");
    }
}
