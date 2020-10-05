/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2020 The University of Waikato, Hamilton, New Zealand.
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

#include <windows.h>

#include "w32-compat.h"
#include "w32-service.h"
#include "debug.h"


static void service_control_handler(DWORD code);

/*
 * Calling CreateEvent with a name that already exists will return a handle
 * to the existing event. This makes it easy to get access to this event from
 * anywhere.
 */
static HANDLE get_stop_event(void) {
    return CreateEvent(NULL, FALSE, FALSE, "amp_stop_service_event");
}



/*
 * XXX Is having the handle static the nicest way to make it available in
 * multiple locations without having to get a new one each time?
 */
static SERVICE_STATUS_HANDLE get_service_handle(void) {
    static SERVICE_STATUS_HANDLE handle = 0;

    if ( handle ) {
        return handle;
    }

    handle = RegisterServiceCtrlHandler(AMP_SERVICE_NAME,
            (LPHANDLER_FUNCTION)service_control_handler);

    if ( !handle ) {
        Log(LOG_WARNING, "Failed to register service control handler: %s",
                sockerr(GetLastError()));
        return NULL;
    }

    return handle;
}



/*
 * Tell the operating system what the current status of the service is.
 */
static int set_service_status(DWORD state) {
    SERVICE_STATUS status;

    Log(LOG_DEBUG, "Setting service status: %d", state);

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;

    if ( state == SERVICE_START_PENDING ) {
        status.dwControlsAccepted = 0;
    } else {
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
            SERVICE_ACCEPT_SHUTDOWN;
    }

    // TODO exit codes?

    if ( !SetServiceStatus(get_service_handle(), &status) ) {
        // TODO terminate service and set status stopped (how to do that
        // without recursively calling this function?
        SetEvent(get_stop_event());
        return -1;
    }

    return 0;
}



/*
 *
 */
static void service_control_handler(DWORD code) {
    switch ( code ) {
        case SERVICE_CONTROL_SHUTDOWN: /* fallthrough */
        case SERVICE_CONTROL_STOP:
            set_service_status(SERVICE_STOP_PENDING);
            SetEvent(get_stop_event());
            break;
    };
}



/*
 *
 */
static DWORD wait_for_message(void *event) {
#if 0
    while ( true ) {
        /* wait for a service exit message, or one of our faked signals */
        event = WaitForMultipleObjects(sizeof(events), events, FALSE, INFINITE);

        switch ( event ) {
            case WAIT_OBJECT_0 + 0:
                event_base_loopbreak();
                break;
            case WAIT_OBJECT_0 + 1:
                // TODO how to get event handles?
                event_active();
                break;
            case WAIT_OBJECT_0 + 2:
                event_active();
                break;
        };
    }
#endif
    // XXX set status here or in the main thread?
    set_service_status(SERVICE_RUNNING);
    WaitForSingleObject(event, INFINITE);
    /*
     * XXX should call event_base_loopbreak() here and exit properly, but will
     * need a reference to the event base to do that
     */
    set_service_status(SERVICE_STOPPED);
    exit(EXIT_SUCCESS);
}



/*
 *
 */
void service_main(DWORD argc, LPTSTR *argv) {
    HANDLE event;

    // XXX check return values
    set_service_status(SERVICE_START_PENDING);

    event = get_stop_event();

    /* start a thread running that will listen for service events */
    if ( CreateThread(NULL, 0, wait_for_message, event, 0, NULL) == NULL ) {
        Log(LOG_WARNING, "Failed to create service thread: %s",
                sockerr(GetLastError()));
        return;
    }

    /* and then run the actual main function that we wanted to run all along */
    actual_main(argc, argv);
}
