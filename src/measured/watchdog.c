#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "watchdog.h"
#include "debug.h"



/*
 * Start a watchdog to kill a test that runs over time.
 */
int start_test_watchdog(test_t *test, timer_t *timerid) {
    assert(test);
    assert(timerid);

    Log(LOG_DEBUG, "Creating watchdog timer of %d seconds for %s test",
            test->max_duration, test->name);

#if 0
    /* TODO every test could get a sigint, give it a chance to log death? */
    if ( test->sigint ) {
        start_watchdog(test->max_duration, SIGINT, timerid);
    }
#endif

    return start_watchdog(test->max_duration, SIGKILL, timerid);
}



/*
 * Start a generic watchdog to trigger a given signal. Generally used to ensure
 * tests exit, sometimes used by other processes that should also not be left
 * running (fetching remote test schedules etc).
 */
int start_watchdog(time_t duration, int signal, timer_t *timerid) {
    struct sigevent sevp;
    struct itimerspec when;

    assert(timerid);

    /* create the timer to send the signal when it expires */
    memset(&sevp, 0, sizeof(sevp));
    sevp.sigev_notify = SIGEV_SIGNAL;
    sevp.sigev_signo = signal;
    sevp.sigev_value.sival_ptr = timerid;

    if ( timer_create(CLOCK_REALTIME, &sevp, timerid) < 0 ) {
        Log(LOG_WARNING, "Failed to create watchdog timer:%s", strerror(errno));
        return -1;
    }

    /* set the timer to expire at the maximum test duration */
    when.it_value.tv_sec = duration;
    when.it_value.tv_nsec = 0;
    when.it_interval.tv_sec = 0;
    when.it_interval.tv_nsec = 0;

    if ( timer_settime(*timerid, 0, &when, NULL) < 0 ) {
        Log(LOG_WARNING, "Failed to set watchdog timer:%s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Disarm and delete the timer that was set up to kill this test process.
 */
int stop_watchdog(timer_t timerid) {
    if ( timer_delete(timerid) < 0 ) {
        Log(LOG_WARNING, "Failed to stop watchdog timer: %s", strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Trigger when receiving SIGCHLD to report on how the process (test) completed.
 * Multiple children can finish at the same time, possibly causing
 * libwandevent not to fire this event for every child, so loop around and
 * consume all the children.
 */
void child_reaper(__attribute__((unused))wand_event_handler_t *ev_hdl,
        __attribute__((unused))int signum,
        __attribute__((unused))void *data) {

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

        /* actually, nothing terminated, we are done */
        if ( infop.si_pid == 0 ) {
            return;
        }

        Log(LOG_DEBUG, "child terminated, pid: %d\n", infop.si_pid);

        switch ( infop.si_code ) {
            case CLD_EXITED:
                /* exited, status is the exit code */
                Log(LOG_DEBUG, "Child %d exited normally (%d)",
                        infop.si_pid, infop.si_status);
                break;

            case CLD_KILLED:
                /* killed, status is the signal number */
                Log(LOG_WARNING, "Child %d was killed (%d)",
                        infop.si_pid, infop.si_status);
                break;

            /* killed, dumped core, status is the signal number */
            case CLD_DUMPED:
                Log(LOG_WARNING, "Child %d was killed abnormally (%d)",
                        infop.si_pid, infop.si_status);
                break;

            default: Log(LOG_WARNING,
                             "Unexpected action for child %s (%d/%d)",
                             infop.si_code, infop.si_status);
                     break;
        };
    }
}
