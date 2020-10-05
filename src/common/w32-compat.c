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

#include <io.h>
#include <libgen.h>
#include <windows.h>
#include <stdio.h>
#include <fcntl.h>

#include "w32-compat.h"


/*
 * XXX can we define a few things so that strerror(errno) can be used
 * everywhere? When should WSAGetLastError() and GetLastError() be used?
 */
char* sockerr(int errcode) {
    /* XXX can I get away with this being static? */
    static char errmsg[256];

    DWORD len = FormatMessageA(
            FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errcode, 0, errmsg, 255, NULL);

    if ( len != 0 ) {
        errmsg[len] = 0;
    } else {
        sprintf(errmsg, "error %d", errcode);
    }

    return errmsg;
}



/*
 * Implement globbing using Windows directory searching functions.
 */
int glob(const char *pattern,
        __attribute__((unused))int flags,
        __attribute__((unused))void *errfunc,
        glob_t *pglob) {

    intptr_t fhandle;
    struct _finddata_t fdata;
    char *directory, *tmp;

    pglob->gl_pathc = 0;
    pglob->gl_pathv = NULL;

    fhandle = _findfirst(pattern, &fdata);

    if ( fhandle < 0 ) {
        /* TODO glob return values aren't checked, but should map error codes */
        // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/findfirst-functions?view=vs-2019
        return -1;
    }

    tmp = strdup(pattern);
    directory = dirname(tmp);

    do {
        char *path;
        asprintf(&path, "%s/%s", directory, fdata.name);

        pglob->gl_pathc++;
        pglob->gl_pathv = realloc(pglob->gl_pathv,
                pglob->gl_pathc * sizeof(char *));
        pglob->gl_pathv[pglob->gl_pathc - 1] = path;
    } while ( _findnext(fhandle, &fdata ) == 0 );

    _findclose(fhandle);

    return 0;
}



/*
 * Free the results from Windows globbing.
 */
void globfree(glob_t *pglob) {
    size_t i;

    for ( i = 0; i < pglob->gl_pathc; i++ ) {
        free(pglob->gl_pathv[i]);
    }

    pglob->gl_pathc = 0;
    pglob->gl_pathv = NULL;
}
