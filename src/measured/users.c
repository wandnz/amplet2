/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2019 The University of Waikato, Hamilton, New Zealand.
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

#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <grp.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "users.h"
#include "debug.h"



/*
 * Change from the root user to a specified non-privileged user, making sure
 * to keep CAP_NET_RAW and CAP_NET_BIND_SERVICE capabilities so that tests
 * can still run. In theory we also need CAP_NET_ADMIN to change
 * type-of-service bits, but that doesn't appear to be correct. We do however
 * need CAP_NET_ADMIN to avoid a bug, so we'll set it anyway:
 * https://github.com/the-tcpdump-group/libpcap/issues/689
 */
int change_user(char *username) {
    struct passwd *pwd;
    cap_t caps;
    cap_value_t cap_list[3] = {
        CAP_NET_RAW,
        CAP_NET_ADMIN,
        CAP_NET_BIND_SERVICE
    };

    if ( !username || strcmp(username, "root") == 0 ) {
        Log(LOG_INFO, "Continuing as root, not dropping permissions");
        return 0;
    }

    Log(LOG_INFO, "Dropping permissions from root to %s", username);

    if ( (pwd = getpwnam(username)) == NULL ) {
        Log(LOG_WARNING, "Failed to lookup user %s", username);
        return -1;
    }

    if ( !CAP_IS_SUPPORTED(CAP_SETFCAP) ||
            !CAP_IS_SUPPORTED(CAP_NET_RAW) ||
            !CAP_IS_SUPPORTED(CAP_NET_ADMIN) ||
            !CAP_IS_SUPPORTED(CAP_NET_BIND_SERVICE) ) {
        return -1;
    }

    /* allow keeping permitted capabilities after dropping root */
    if ( prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 ) {
        return -1;
    }

    /* drop any ancillary groups */
    if ( setgroups(0, NULL) != 0 ) {
        return -1;
    }

    /* set the group and user */
    if ( setgid(pwd->pw_gid) != 0 ) {
        return -1;
    }

    if ( setuid(pwd->pw_uid) != 0 ) {
        return -1;
    }

    /* change to the users home directory just to be tidy */
    if ( chdir(pwd->pw_dir) != 0 ) {
        return -1;
    }

    /* double check we can't regain root */
    if ( setuid(0) == 0 || seteuid(0) == 0 ) {
        Log(LOG_WARNING, "possible to regain root privileges!\n");
        return -1;
    }

    /*
     * after changing from zero to non-zero uid all capabilities are cleared
     * from the effective set, so they need to be added back.
     */
    if ( (caps = cap_get_proc()) == NULL ) {
        return -1;
    }

    if ( cap_set_flag(caps, CAP_EFFECTIVE, 3, cap_list, CAP_SET) == -1 ) {
        return -1;
    }

    if ( cap_set_proc(caps) == -1 ) {
        return -1;
    }

    if ( cap_free(caps) == -1 ) {
        return -1;
    }

    return 0;
}


int mkdir_and_chown(char *username, const char *dir, mode_t mode) {
    assert(dir);

    Log(LOG_DEBUG, "Creating directory %s", dir);

    /* try to create the directory, do nothing if it already exists */
    if ( mkdir(dir, mode) != 0 ) {
        if ( errno != EEXIST ) {
            Log(LOG_WARNING, "Failed to create directory %s: %s", dir,
                    strerror(errno));
            return -1;
        }
    }

    /* if a username is given then change ownership of the directory */
    if ( username ) {
        struct passwd *pwd;

        Log(LOG_DEBUG, "Changing directory ownership to %s", username);

        if ( (pwd = getpwnam(username)) == NULL ) {
            Log(LOG_WARNING, "Failed to lookup user %s", username);
            return -1;
        }

        if ( chown(dir, pwd->pw_uid, pwd->pw_gid) != 0 ) {
            Log(LOG_WARNING, "Failed to change ownership of dir %s to %s: %s",
                    dir, username, strerror(errno));
            return -1;
        }
    }

    return 0;
}
