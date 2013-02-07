#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([amplet2], [0.1], [amp@wand.net.nz])
#AC_CONFIG_SRCDIR([src/measured/measured.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

# By default install everything into our own directory
AC_PREFIX_DEFAULT(/usr/local/amp)

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SEARCH_LIBS(dlopen, dl)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h, sys/inotify.h])

# Checks for typedefs, structures, and compiler characteristics.
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -g -Wall -W -Wmissing-prototypes"
fi

# Checks for library functions.
AC_CHECK_LIB([confuse], [cfg_init],,confuse_found=0)
if test "$confuse_found" = 0; then
    AC_MSG_ERROR(Required library libconfuse not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([wandevent], [wand_event_init],,event_found=0)
if test "$event_found" = 0; then
    AC_MSG_ERROR(Required library libwandevent not found; use LDFLAGS to specify library location)
fi

# Checks to enable the various tests in AMP
AC_ARG_ENABLE(skeleton,
    AC_HELP_STRING([--enable-skeleton], 
	[Enable the skeleton test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_skeleton_test=true ;;
    false) ;&
    no)	 want_skeleton_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-skeleton) ;;
    esac],
    [want_skeleton_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_SKELETON_TEST, [test x"$want_skeleton_test" = xtrue])

AC_ARG_ENABLE(icmp,
    AC_HELP_STRING([--enable-icmp], 
	[Enable the icmp test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_icmp_test=true ;;
    false) ;&
    no)	 want_icmp_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-icmp) ;;
    esac],
    [want_icmp_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_ICMP_TEST, 
	[test x"$want_icmp_test" = xtrue])

AC_ARG_ENABLE(dns,
    AC_HELP_STRING([--enable-dns], 
	[Enable the dns test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_dns_test=true ;;
    false) ;&
    no)	 want_dns_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-dns) ;;
    esac],
    [want_dns_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_DNS_TEST, 
	[test x"$want_dns_test" = xtrue])


AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/measured/Makefile
                 src/common/Makefile
                 src/tests/Makefile
                 src/tests/skeleton/Makefile
                 src/tests/icmp/Makefile
                 src/tests/dns/Makefile
                 src/xferd/Makefile])
AC_OUTPUT

reportopt() {
    if test x"$2" = xtrue -o x"$2" = xyes -o x"$2" = x1; then
	AC_MSG_NOTICE([$1: Yes])
    else
	AC_MSG_NOTICE([$1: No])
	    fi
}

reportopt "Compiled with skeleton test support" $want_skeleton_test
reportopt "Compiled with icmp test support" $want_icmp_test
reportopt "Compiled with dns test support" $want_dns_test
