#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([amplet2], [0.9.0], [amp@wand.net.nz])
#AC_CONFIG_SRCDIR([src/measured/measured.c])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])


# libtool will do what it wants with the values given for CURRENT:REVISION:AGE
# but it should all work out ok even if it looks wrong. See:
#   https://autotools.io/libtool/version.html
#
# How to update version:
#   https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
#
# Versions:
#   amplet2-0.8.4 and earlier: no versioning
#   amplet2-0.9.0: 1:0:0 (ABI version 1)
LIBAMP_LIBTOOL_VERSION=1:0:0
AC_SUBST(LIBAMP_LIBTOOL_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for flex
AC_PROG_LEX
if test "$LEX" != "flex"; then
        AC_MSG_ERROR(Required program flex not found)
fi

# Checks for libraries.
AC_SEARCH_LIBS(dlopen, dl)

# Checks for typedefs, structures, and compiler characteristics.
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -g -Wall -W -Wmissing-prototypes -Wextra -Wstrict-prototypes -O2"
fi

# Checks for library functions.

# TODO might be able to tidy up some of these? If every program links with the
# same library then just leave the action-if-found empty so it gets added to
# the global $LIBS
AC_CHECK_LIB([rt], [timer_create],lrt_found=1,lrt_found=0)
if test "$lrt_found" = 0; then
    AC_MSG_ERROR(Required library librt not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([crypto], [EVP_DigestInit_ex],crypto_found=1,crypto_found=0)
if test "$crypto_found" = 0; then
    AC_MSG_ERROR(Required library libcrypto not found; use LDFLAGS to specify library location)
fi

ssl_found=0
AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [ssl_found=1])
AC_CHECK_LIB([ssl], [SSL_library_init], [ssl_found=1])
if test "$ssl_found" = 0; then
    AC_MSG_ERROR(Required library libssl not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([confuse], [cfg_init],confuse_found=1,confuse_found=0)
if test "$confuse_found" = 0; then
    AC_MSG_ERROR(Required library libconfuse not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([wandevent], [wand_add_fd],event_found=1,event_found=0)
if test "$event_found" = 0; then
    AC_MSG_ERROR(Required library libwandevent3 not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([rabbitmq], [amqp_new_connection],rabbit_found=1,rabbit_found=0)
if test "$rabbit_found" = 0; then
    AC_MSG_ERROR(Required library librabbitmq not found; use LDFLAGS to specify library location)
fi

AC_CHECK_HEADER(amqp.h, ampq_h_found=1, amqp_h_found=0)
if test "$amqp_h_found" = 0; then
    AC_MSG_ERROR(Required headers for librabbitmq not found; use CFLAGS to specify header location)
fi

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
    [[#include <amqp.h>]],
    [[amqp_sasl_method_enum a = AMQP_SASL_METHOD_EXTERNAL;]])],
[], [AC_MSG_ERROR(Library librabbitmq missing AMQP_SASL_METHOD_EXTERNAL, ensure version >= 0.7.1)])

AC_CHECK_LIB([pthread], [pthread_create],pthread_found=1,pthread_found=0)
if test "$pthread_found" = 0; then
    AC_MSG_ERROR(Required library libpthread not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([yaml], [yaml_parser_initialize],yaml_found=1,yaml_found=0)
if test "$yaml_found" = 0; then
    AC_MSG_ERROR(Required library libyaml not found; use LDFLAGS to specify library location)
fi

AC_CHECK_LIB([unbound], [ub_ctx_create],unbound_found=1,unbound_found=0)
if test "$unbound_found" = 0; then
    AC_MSG_ERROR(Required library libunbound not found; use LDFLAGS to specify library location)
fi

# we use libcurl to fetch remote schedules and to perform the http test
AC_CHECK_LIB(curl, curl_global_init, libcurl_found=1, libcurl_found=0)
if test "$libcurl_found" = 0; then
    AC_MSG_ERROR(Required library libcurl not found; use LDFLAGS to specify library location)
fi
AC_CHECK_HEADER(curl/curl.h, curl_h_found=1, curl_h_found=0)
if test "$curl_h_found" = 0; then
    AC_MSG_ERROR(Required headers for libcurl not found; use CFLAGS to specify header location)
fi

# make sure google protocol buffer C libraries exist
AC_CHECK_LIB(protobuf-c, protobuf_c_message_pack, libprotobufc_found=1, libprotobufc_found=0)
if test "$libprotobufc_found" = 0; then
    AC_MSG_ERROR(Required library libprotobuf-c not found; use LDFLAGS to specify library location)
fi
AC_CHECK_HEADER(google/protobuf-c/protobuf-c.h, protobuf_h_found=1, protobuf_h_found=0)
if test "$protobuf_h_found" = 0; then
    AC_MSG_ERROR(Required headers for protobuf-c not found; use CFLAGS to specify header location)
fi

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

AC_ARG_ENABLE(remoteskeleton,
    AC_HELP_STRING([--enable-remoteskeleton],
	[Enable the remote skeleton test (default: no)]),
    [case "${enableval}" in
    true) ;&
    yes) want_remoteskeleton_test=true ;;
    false) ;&
    no)	 want_remoteskeleton_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-skeleton) ;;
    esac],
    [want_remoteskeleton_test=false])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_REMOTESKELETON_TEST, [test x"$want_remoteskeleton_test" = xtrue])

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
AM_CONDITIONAL(WANT_ICMP_TEST, [test x"$want_icmp_test" = xtrue])

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
AM_CONDITIONAL(WANT_TRACEROUTE_TEST, [test x"$want_traceroute_test" = xtrue])

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
AM_CONDITIONAL(WANT_DNS_TEST, [test x"$want_dns_test" = xtrue])

AC_ARG_ENABLE(throughput,
    AC_HELP_STRING([--enable-throughput],
	[Enable the throughput test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_throughput_test=true ;;
    false) ;&
    no)	 want_throughput_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-throughput) ;;
    esac],
    [want_throughput_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_THROUGHPUT_TEST, [test x"$want_throughput_test" = xtrue])

AC_ARG_ENABLE(tcpping,
    AC_HELP_STRING([--enable-tcpping],
	[Enable the tcpping test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_tcpping_test=true ;;
    false) ;&
    no)	 want_tcpping_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-tcpping) ;;
    esac],
    [want_tcpping_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_TCPPING_TEST, [test x"$want_tcpping_test" = xtrue])

if test x"$want_tcpping_test" = xtrue; then
    AC_CHECK_LIB([pcap], [pcap_next], pcap_found=1, pcap_found=0)
    AC_CHECK_LIB([pcap], [pcap_set_immediate_mode], pcap_imm_found=1, pcap_imm_found=0)

    if test "$pcap_found" = 0; then
        AC_MSG_ERROR(libpcap is required for tcpping but not found; use LDFLAGS to specify library location or disable tcpping test by setting --enable-tcpping=no)
    fi

    if test "$pcap_imm_found" = 1; then
        AC_DEFINE([HAVE_PCAP_IMMEDIATE_MODE], [1], [Define to 1 if you have the libpcap pcap_set_immediate_mode function])
    fi
fi

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
AM_CONDITIONAL(WANT_HTTP_TEST, [test x"$want_http_test" = xtrue])
if test x"$want_http_test" = xtrue; then
    # check there is a lexer to build the scanner
    AM_PROG_LEX

    # Check if the curl library is new enough to support curl_multi_timeout
    AC_CHECK_LIB(curl, curl_multi_timeout, AC_DEFINE([HAVE_CURL_MULTI_TIMEOUT], [1], [Define to 1 if you have the libcurl curl_multi_timeout function]),)

fi

AC_ARG_ENABLE(udpstream,
    AC_HELP_STRING([--enable-udpstream],
	[Enable the udpstream test (default: yes)]),
    [case "${enableval}" in
    true) ;&
    yes) want_udpstream_test=true ;;
    false) ;&
    no)	 want_udpstream_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-udpstream) ;;
    esac],
    [want_udpstream_test=true])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_UDPSTREAM_TEST, [test x"$want_udpstream_test" = xtrue])

AC_ARG_ENABLE(youtube,
    AC_HELP_STRING([--enable-youtube],
	[Enable the youtube test (default: no)]),
    [case "${enableval}" in
    true) ;&
    yes) want_youtube_test=true ;;
    false) ;&
    no)	 want_youtube_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-youtube) ;;
    esac],
    [want_youtube_test=false])

CHROMIUM_INCLUDE_DIR=""
AC_ARG_WITH(chromium-build,
    AC_HELP_STRING([--with-chromium-build=DIR],
        [Specify the base location of the built chromium libraries]),
        [CHROMIUM_BUILD_DIR="${withval}" CHROMIUM_INCLUDE_DIR="-I${withval}/gen" want_youtube_test=true])
AC_SUBST(CHROMIUM_BUILD_DIR)

AC_ARG_WITH(chromium-includes,
    AC_HELP_STRING([--with-chromium-includes=DIR],
        [Specify the location of the chromium headers]),
        [CHROMIUM_INCLUDE_DIR+=" -I${withval}" want_youtube_test=true])
AC_SUBST(CHROMIUM_INCLUDE_DIR)

# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_YOUTUBE_TEST, [test x"$want_youtube_test" = xtrue])

AC_ARG_ENABLE(fastping,
    AC_HELP_STRING([--enable-fastping],
        [Enable the fastping test (default: no)]),
    [case "${enableval}" in
    true) ;&
    yes) want_fastping_test=true ;;
    false) ;&
    no)  want_fastping_test=false ;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-fastping) ;;
    esac],
    [want_fastping_test=false])
# using AM_CONDITIONAL propagates this value through to all Makefile.am files
AM_CONDITIONAL(WANT_FASTPING_TEST, [test x"$want_fastping_test" = xtrue])


# Set default CFLAGS including the AMP_CONFIG_DIR and AMP_TEST_DIR
AC_SUBST([AM_CFLAGS], ["-rdynamic -g -Wall -W -D_GNU_SOURCE -DAMP_CONFIG_DIR=\\\"\$(sysconfdir)/\$(PACKAGE)\\\" -DAMP_TEST_DIRECTORY=\\\"\$(libdir)/\$(PACKAGE)/tests\\\" -DAMP_LOG_DIR=\\\"\$(localstatedir)/log/\\\""])


AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/measured/Makefile
                 src/measured/test/Makefile
                 src/measured/etc/Makefile
                 src/common/Makefile
                 src/common/test/Makefile
                 src/tests/Makefile
                 src/tests/python/Makefile
                 src/tests/skeleton/Makefile
                 src/tests/icmp/Makefile
                 src/tests/icmp/test/Makefile
                 src/tests/dns/Makefile
                 src/tests/dns/test/Makefile
                 src/tests/traceroute/Makefile
                 src/tests/traceroute/test/Makefile
                 src/tests/tcpping/Makefile
                 src/tests/tcpping/test/Makefile
                 src/tests/http/Makefile
                 src/tests/http/test/Makefile
                 src/tests/throughput/Makefile
                 src/tests/throughput/test/Makefile
                 src/tests/remoteskeleton/Makefile
                 src/tests/udpstream/Makefile
                 src/tests/udpstream/test/Makefile
                 src/tests/youtube/Makefile
                 src/tests/fastping/Makefile])
                 #src/tests/youtube/test/Makefile
                 #src/tests/fastping/test/Makefile])
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
reportopt "Compiled with remote skeleton test support" $want_remoteskeleton_test
reportopt "Compiled with icmp test support" $want_icmp_test
reportopt "Compiled with traceroute test support" $want_traceroute_test
reportopt "Compiled with dns test support" $want_dns_test
reportopt "Compiled with http test support" $want_http_test
reportopt "Compiled with throughput test support" $want_throughput_test
reportopt "Compiled with tcpping test support" $want_tcpping_test
reportopt "Compiled with udpstream test support" $want_udpstream_test
reportopt "Compiled with youtube test support" $want_youtube_test
reportopt "Compiled with fastping test support" $want_fastping_test
