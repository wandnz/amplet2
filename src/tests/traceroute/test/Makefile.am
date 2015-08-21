TESTS=traceroute_register.test traceroute_ipv4probe.test traceroute_ipv6probe.test
check_PROGRAMS=traceroute_register.test traceroute_ipv4probe.test traceroute_ipv6probe.test

traceroute_register_test_SOURCES=traceroute_register_test.c ../traceroute.c ../as.c
nodist_traceroute_register_test_SOURCES=../traceroute.pb-c.c
traceroute_register_test_CFLAGS=-rdynamic -DUNIT_TEST
traceroute_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lwandevent -lprotobuf-c

traceroute_ipv4probe_test_SOURCES=traceroute_ipv4probe_test.c ../traceroute.c ../as.c
nodist_traceroute_ipv4probe_test_SOURCES=../traceroute.pb-c.c
traceroute_ipv4probe_test_CFLAGS=-rdynamic -DUNIT_TEST
traceroute_ipv4probe_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lwandevent -lprotobuf-c

traceroute_ipv6probe_test_SOURCES=traceroute_ipv6probe_test.c ../traceroute.c ../as.c
nodist_traceroute_ipv6probe_test_SOURCES=../traceroute.pb-c.c
traceroute_ipv6probe_test_CFLAGS=-rdynamic -DUNIT_TEST
traceroute_ipv6probe_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lwandevent -lprotobuf-c

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

