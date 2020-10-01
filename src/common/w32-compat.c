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
