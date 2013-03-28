#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>


#include "schedule.h"
#include "watchdog.h"
#include "debug.h"



/*
 * Add a watchdog timer that will kill a test should it run too long. The
 * maximum duration is based on the test (determined at registration time)
 * and passed in as a maximum number of seconds.
 */
void add_test_watchdog(wand_event_handler_t *ev_hdl, pid_t pid, uint16_t max) {
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
    timer->expire = wand_calc_expire(ev_hdl, max, 0);
    timer->callback = kill_running_test;
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(ev_hdl, timer);
}



/*
 * Cancel the test watchdog when a test successfully completes. The task to
 * terminate the test needs to be removed from the schedule.
 */
static void cancel_test_watchdog(wand_event_handler_t *ev_hdl, pid_t pid) {
    struct wand_timer_t *timer = ev_hdl->timers;
    struct wand_timer_t *tmp;
    schedule_item_t *item;

    /* search the list of timers to find the watchdog for this pid */
    while ( timer != NULL ) {
	tmp = timer;
	timer = timer->next;
	if ( tmp->data != NULL ) {
	    item = (schedule_item_t *)tmp->data;
	    if ( item->type == EVENT_CANCEL_TEST ) {
		/* cancel this timer if it has the pid we want */
		if ( item->data.kill->pid == pid ) {
		    wand_del_timer(ev_hdl, tmp);
		    if ( item->data.kill != NULL ) {
			free(item->data.kill);
		    }
		    free(item);
		    free(tmp);
		    return;
		}
	    }
	}
    }
    /* if the watchdog for the pid doesn't exist, something has gone wrong */
    assert(0);
}



/*
 * Trigger when receiving SIGCHLD to tidy up child processes (tests) and
 * remove any active watchdog tasks for that test. Multiple children can
 * finish at the same time, possibly causing libwandevent not to fire this
 * event for every child, so loop around and consume all the children.
 */
void child_reaper(__attribute__((unused))struct wand_signal_t *signal) {
    siginfo_t infop;

    while ( 1 ) {
	/* set this to zero and then we can tell if waitid worked or not */
	infop.si_pid = 0;

	if ( waitid(P_ALL, 0, &infop, WNOHANG | WEXITED) < 0 ) {
	    /* because we loop to consume all children, sometimes we can
	     * call this function in response to a SIGCHLD but there are no
	     * children of this process left running - that's ok.
	     */
	    if ( errno != ECHILD ) {
		perror("waitid");
	    }
	    return;
	}

	Log(LOG_DEBUG, "child terminated, pid: %d\n", infop.si_pid);

	/* actually, nothing terminated, we are done */
	if ( infop.si_pid == 0 ) {
	    return;
	}

	assert(infop.si_pid > 0);

	/* if the task ended normally then remove the scheduled kill */
	if ( infop.si_pid > 0 && infop.si_code == CLD_EXITED ) {
	    cancel_test_watchdog(signal->data, infop.si_pid);
	} else {
	    /* TODO do we want to report on killed tests? */
	}
    }
}



/*
 * Kill a test process that has run for too long. The SIGCHLD handler will
 * take care of tidying everything up.
 */
void kill_running_test(struct wand_timer_t *timer) {
    schedule_item_t *item = (schedule_item_t *)timer->data;

    assert(item);
    assert(item->type == EVENT_CANCEL_TEST);
    assert(item->data.kill);
    assert(item->data.kill->pid > 0);

    /* TODO send SIGINT first like amp1 did? killpg() vs kill() */
    /* kill the test */
    if ( kill(item->data.kill->pid, SIGKILL) < 0 ) {
	perror("kill");
    }

    /* tidy up the watchdog timer that just fired, it is no longer needed */
    free(item->data.kill);
    free(item);
    free(timer);
}
