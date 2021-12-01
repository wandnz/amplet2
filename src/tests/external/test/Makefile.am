TESTS=external_register.test external_report.test
check_PROGRAMS=external_register.test external_report.test

check_LTLIBRARIES=testexternal.la
testexternal_la_SOURCES=../external.c
nodist_testexternal_la_SOURCES=../external.pb-c.c
testexternal_la_CFLAGS=-rdynamic -DUNIT_TEST -D_GNU_SOURCE -DAMP_EXTERNAL_BIN_DIRECTORY=\"$(libdir)/$(PACKAGE)/external\"
testexternal_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

external_register_test_SOURCES=external_register_test.c
external_register_test_LDADD=testexternal.la

external_report_test_SOURCES=external_report_test.c
external_report_test_LDADD=testexternal.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
AM_CPPFLAGS+=-I../
