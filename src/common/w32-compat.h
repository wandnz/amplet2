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

#ifndef _COMMON_W32COMPAT_H
#define _COMMON_W32COMPAT_H

#include "fmemopen.h"

#define dlopen(filename, flags) LoadLibrary(filename)
#define dlsym(hdl, func) GetProcAddress(hdl, func)
#define dlclose(hdl) FreeLibrary(hdl)

#define random() rand()
#define srandom(seed) srand(seed)

//#define ctime_r(timep, buf) ctime_s(buf, sizeof(buf), timep)
#define timegm(tm) _mkgmtime(tm)
#define mkdir(pathname, mode) mkdir(pathname)

/* rename on windows won't overwrite an existing file, so make it */
#define rename(oldpath, newpath) MoveFileEx(oldpath, newpath, MOVEFILE_REPLACE_EXISTING)

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef SIGUSR1
#define SIGUSR1 10
#endif

#ifndef s6_addr16
#define s6_addr16       u.Word
#endif

/* global reference to this event so that threads can fake sending a SIGUSR1 */
struct event *signal_usr1;

/* reimplement glob using _findfirst and _findnext */
typedef struct {
    size_t gl_pathc;
    char **gl_pathv;
} glob_t;

int glob(const char *pattern, int flags, void *errfunc, glob_t *pglob);
void globfree(glob_t *pglob);
char* sockerr(int errcode);

#endif
