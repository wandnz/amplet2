TESTS=tcpping_register.test tcpping_report.test tcpping_unresolved_target.test
check_PROGRAMS=tcpping_register.test tcpping_report.test tcpping_unresolved_target.test

check_LTLIBRARIES=testtcpping.la
testtcpping_la_SOURCES=../tcpping.c ../pcapcapture.c
nodist_testtcpping_la_SOURCES=../tcpping.pb-c.c
testtcpping_la_CFLAGS=-rdynamic -DUNIT_TEST
testtcpping_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lpcap -lprotobuf-c -levent

tcpping_register_test_SOURCES=tcpping_register_test.c
tcpping_register_test_LDADD=testtcpping.la

tcpping_report_test_SOURCES=tcpping_report_test.c
tcpping_report_test_LDADD=testtcpping.la

tcpping_unresolved_target_test_SOURCES=tcpping_unresolved_target_test.c
tcpping_unresolved_target_test_LDADD=testtcpping.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
AM_CPPFLAGS+=-I../
