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
