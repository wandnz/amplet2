TESTS=traceroute_register.test traceroute_ipv4probe.test traceroute_ipv6probe.test traceroute_unresolved_target.test
check_PROGRAMS=traceroute_register.test traceroute_ipv4probe.test traceroute_ipv6probe.test traceroute_unresolved_target.test

check_LTLIBRARIES=testtraceroute.la
testtraceroute_la_SOURCES=../traceroute.c ../as.c
nodist_testtraceroute_la_SOURCES=../traceroute.pb-c.c
testtraceroute_la_CFLAGS=-rdynamic -DUNIT_TEST
testtraceroute_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lwandevent -lprotobuf-c

traceroute_register_test_SOURCES=traceroute_register_test.c
traceroute_register_test_LDADD=testtraceroute.la

traceroute_ipv4probe_test_SOURCES=traceroute_ipv4probe_test.c
traceroute_ipv4probe_test_LDADD=testtraceroute.la

traceroute_ipv6probe_test_SOURCES=traceroute_ipv6probe_test.c
traceroute_ipv6probe_test_LDADD=testtraceroute.la

traceroute_unresolved_target_test_SOURCES=traceroute_unresolved_target_test.c
traceroute_unresolved_target_test_LDADD=testtraceroute.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../ -I../../../common/
