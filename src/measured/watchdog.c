/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#include <signal.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/time.h>

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
 * libevent not to fire this event for every child, so loop around and
 * consume all the children.
 */
void child_reaper(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        __attribute__((unused))void *evdata) {

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
