/*
 * Copyright (c) 2017  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * See: https://github.com/martinh/libconfuse/blob/master/src/fmemopen.c
 */


#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <windows.h>

#include "fmemopen.h"

FILE *fmemopen(void *buf, size_t len, __attribute__((unused))const char *type)
{
    int fd;
    FILE *fp;
    char tp[MAX_PATH - 13];
    char fn[MAX_PATH + 1];

    if (!GetTempPathA(sizeof(tp), tp))
        return NULL;

    if (!GetTempFileNameA(tp, "confuse", 0, fn))
        return NULL;

    fd = _open(fn,
            _O_CREAT | _O_RDWR | _O_SHORT_LIVED | _O_TEMPORARY | _O_BINARY,
            _S_IREAD | _S_IWRITE);
    if (fd == -1)
        return NULL;

    fp = _fdopen(fd, "w+");
    if (!fp) {
        _close(fd);
        return NULL;
    }

    fwrite(buf, len, 1, fp);
    rewind(fp);

    return fp;
}



/*
 * Open a stream for writing to a buffer and return a pointer to the buffer.
 *
 * Unlike the POSIX versions of this function, don't bother dynamically
 * resizing the buffer, and return the pointer immediately rather than
 * when the stream is closed. The pointer will need to be explicitly read
 * from as I'm not hooking into the FILE close handler to populate it.
 *
 * XXX can I use fmemopen instead of duplicating half of it here?
 */
FILE *open_memstream(
        __attribute__((unused))char **ptr,
        __attribute__((unused))size_t *sizeloc) {
    int fd;
    FILE *fp;
    char tmppath[MAX_PATH + 1]; //XXX - 14? then need to check length returned
    char tmpfile[MAX_PATH + 1]; // XXX

    if ( GetTempPathA(sizeof(tmppath), tmppath) == 0 ) {
        /*
         * TODO what error to return (convert GetLastError to errno?),
         * alternatively, change the caller to not use errno?
         */
        errno = EPERM;
        return NULL;
    }

    if ( GetTempFileNameA(tmppath, "amp", 0, tmpfile) == 0 ) {
        /*
         * TODO what error to return (convert GetLastError to errno?),
         * alternatively, change the caller to not use errno?
         */
        errno = EPERM;
        return NULL;
    }

    /* try really hard to make this file exist only in memory */
    fd = open(tmpfile,
            _O_CREAT | _O_RDWR | _O_SHORT_LIVED | _O_TEMPORARY | _O_BINARY,
            _S_IREAD | _S_IWRITE);

    if ( fd < 0 ) {
        /* TODO errno? */
        return NULL;
    }

    fp = fdopen(fd, "w+");

    if ( fp == NULL ) {
        /* TODO errno? */
        close(fd);
        return NULL;
    }

    return fp;
}
