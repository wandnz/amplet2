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

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "ampresolv.h"
#include "debug.h"
#include "localsock.h"

/*
 * Create a local unix socket on the given path.
 */
int initialise_local_socket(char *path) {
    int sock;
    struct sockaddr_un addr;

    Log(LOG_DEBUG, "Creating local socket at '%s'", path);

    /*
     * We shouldn't be able to get to here if there is already an amp
     * process running with our name, so clearing out the socket should
     * be a safe thing to do.
     */
    if ( access(path, F_OK) == 0 ) {
        Log(LOG_DEBUG, "Socket '%s' exists, removing", path);
        if ( unlink(path) < 0 ) {
            Log(LOG_WARNING, "Failed to remove old socket '%s': %s", path,
                    strerror(errno));
            return -1;
        }
    }

    /* start listening on a unix socket */
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, UNIX_PATH_MAX, "%s", path);

    if ( (sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ) {
        Log(LOG_WARNING, "Failed to open local socket: %s", strerror(errno));
        return -1;
    }

    if ( bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
        Log(LOG_WARNING, "Failed to bind local socket: %s", strerror(errno));
        return -1;
    }

    if ( listen(sock, MEASURED_MAX_SOCKET_BACKLOG) < 0 ) {
        Log(LOG_WARNING, "Failed to listen on local socket: %s",
                strerror(errno));
        return -1;
    }

    return sock;
}
