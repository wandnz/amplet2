TESTS=fastping_register.test fastping_unresolved_target.test
check_PROGRAMS=fastping_register.test fastping_unresolved_target.test

check_LTLIBRARIES=testfastping.la
testfastping_la_SOURCES=../fastping.c
nodist_testfastping_la_SOURCES=../fastping.pb-c.c
testfastping_la_CFLAGS=-rdynamic -DUNIT_TEST
testfastping_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c -lm -lpcap

fastping_register_test_SOURCES=fastping_register_test.c
fastping_register_test_LDADD=testfastping.la

fastping_unresolved_target_test_SOURCES=fastping_unresolved_target_test.c
fastping_unresolved_target_test_LDADD=testfastping.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../../common/
