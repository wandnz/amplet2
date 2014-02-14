#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([amplet2], [0.1.13], [amp@wand.net.nz])
#AC_CONFIG_SRCDIR([src/measured/measured.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SEARCH_LIBS(dlopen, dl)

# Checks for typedefs, structures, and compiler characteristics.
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -g -Wall -W -Wmissing-prototypes -Wextra -Wstrict-prototypes -O2"
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

AC_CHECK_LIB([rabbitmq], [amqp_new_connection],,rabbit_found=0)
if test "$rabbit_found" = 0; then
    AC_MSG_ERROR(Required library librabbitmq not found; use LDFLAGS to specify library location)
fi

# we use libcurl to fetch remote schedules and to perform the http test
AC_CHECK_LIB(curl, curl_global_init, libcurl_found=1, libcurl_found=0)
if test "$libcurl_found" = 0; then
    AC_MSG_ERROR(Required library libcurl not found; use LDFLAGS to specify library location)
fi
AC_CHECK_HEADER(curl/curl.h, curl_h_found=1, curl_h_found=0)
if test "$curl_h_found" = 0; then
    AC_MSG_ERROR(Required headers for libcurl not found; use CLFAGS to specify header location)
fi

# check if we have the web10g library, it's ok for it to be missing
AC_CHECK_LIB([estats], [estats_nl_client_init],
        [AM_CONDITIONAL(HAVE_ESTATS, true)],
        [AM_CONDITIONAL(HAVE_ESTATS, false)])

AC_ARG_ENABLE(python,
    AC_HELP_STRING([--enable-python],
	[Enable the python data exporting (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_python=true ;;
    false) ;&
    no)	 want_python=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-python) ;;
    esac],
    [want_python=true])

AM_CONDITIONAL(WANT_PYTHON, [test x"$want_python" = xtrue])

if test x"$want_python" = xtrue; then
    AM_PATH_PYTHON([2.6])
fi

# Enable logging via syslog
AC_ARG_ENABLE(syslog,
    AC_HELP_STRING([--enable-syslog],
	[Enable logging via syslog (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_syslog=true ;;
    false) ;&
    no)	 want_syslog=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-syslog) ;;
    esac],
    [want_syslog=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_SYSLOG, [test x"$want_syslog" = xtrue])
if test x"$want_syslog" = xtrue; then
    AC_DEFINE([LOG_TO_SYSLOG], [1], [Define to 1 if you want to log via syslog])
fi


# Checks to enable the various tests in AMP
AC_ARG_ENABLE(skeleton,
    AC_HELP_STRING([--enable-skeleton],
	[Enable the skeleton test (default: no)]),
    [case "${enableval}" in
    true) ;&
    yes) want_skeleton_test=true ;;
    false) ;&
    no)	 want_skeleton_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-skeleton) ;;
    esac],
    [want_skeleton_test=false])
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

AC_ARG_ENABLE(traceroute,
    AC_HELP_STRING([--enable-traceroute],
	[Enable the traceroute test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_traceroute_test=true ;;
    false) ;&
    no)	 want_traceroute_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-traceroute) ;;
    esac],
    [want_traceroute_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_TRACEROUTE_TEST,
	[test x"$want_traceroute_test" = xtrue])

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

AC_ARG_ENABLE(throughput,
    AC_HELP_STRING([--enable-throughput],
	[Enable the throughput test (default: no)]),
    [case "${enableval}" in
    true) ;&
    yes) want_throughput_test=true ;;
    false) ;&
    no)	 want_throughput_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-throughput) ;;
    esac],
    [want_throughput_test=false])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_THROUGHPUT_TEST,
	[test x"$want_throughput_test" = xtrue])

AC_ARG_ENABLE(http,
    AC_HELP_STRING([--enable-http],
	[Enable the http test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_http_test=true ;;
    false) ;&
    no)	 want_http_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-http) ;;
    esac],
    [want_http_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_HTTP_TEST,
	[test x"$want_http_test" = xtrue])
if test x"$want_http_test" = xtrue; then
    # check there is a lexer to build the scanner
    AM_PROG_LEX

    # Check if the curl library is new enough to support curl_multi_timeout
    AC_CHECK_LIB(curl, curl_multi_timeout, AC_DEFINE([HAVE_CURL_MULTI_TIMEOUT], [1], [Define to 1 if you have the libcurl curl_multi_timeout function]),)

fi



AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/measured/Makefile
                 src/measured/test/Makefile
                 src/measured/etc/Makefile
                 src/common/Makefile
                 src/tests/Makefile
                 src/tests/python/Makefile
                 src/tests/skeleton/Makefile
                 src/tests/icmp/Makefile
                 src/tests/icmp/test/Makefile
                 src/tests/dns/Makefile
                 src/tests/traceroute/Makefile
                 src/tests/traceroute/test/Makefile
                 src/tests/http/Makefile
                 src/tests/throughput/Makefile
                 src/xferd/Makefile])
AC_OUTPUT

reportopt() {
    if test x"$2" = xtrue -o x"$2" = xyes -o x"$2" = x1; then
	AC_MSG_NOTICE([$1: Yes])
    else
	AC_MSG_NOTICE([$1: No])
	    fi
}

reportopt "Compiled with python reporting support" $want_python
reportopt "Compiled with syslog logging" $want_syslog
reportopt "Compiled with skeleton test support" $want_skeleton_test
reportopt "Compiled with icmp test support" $want_icmp_test
reportopt "Compiled with dns test support" $want_dns_test
reportopt "Compiled with http test support" $want_http_test
reportopt "Compiled with throughput test support" $want_throughput_test
