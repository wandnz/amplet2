#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([amplet2], [0.1], [amp@wand.net.nz])
#AC_CONFIG_SRCDIR([src/measured/measured.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h, sys/inotify.h])

# Checks for typedefs, structures, and compiler characteristics.
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -g -Wall -W -Wmissing-prototypes"
fi

# Checks for library functions.
AC_CHECK_LIB([wandevent], [wand_event_init],,event_found=0)
if test "$event_found" = 0; then
    AC_MSG_ERROR(Required library libwandevent not found; use LDFLAGS to specify library location)
fi

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/measured/Makefile])
AC_OUTPUT
