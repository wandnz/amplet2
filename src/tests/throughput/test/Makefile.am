TESTS=throughput_register.test throughput_hello.test throughput_ready.test throughput_request.test throughput_report.test
check_PROGRAMS=throughput_register.test throughput_hello.test throughput_ready.test throughput_request.test throughput_report.test

check_LTLIBRARIES=testthroughput.la
testthroughput_la_SOURCES=../throughput.c ../throughput_server.c ../throughput_client.c ../throughput_common.c
nodist_testthroughput_la_SOURCES=../throughput.pb-c.c
testthroughput_la_CFLAGS=-rdynamic -DUNIT_TEST
testthroughput_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

throughput_register_test_SOURCES=throughput_register_test.c
throughput_register_test_LDADD=testthroughput.la

throughput_hello_test_SOURCES=throughput_hello_test.c
throughput_hello_test_LDADD=testthroughput.la

throughput_ready_test_SOURCES=throughput_ready_test.c
throughput_ready_test_LDADD=testthroughput.la

throughput_request_test_SOURCES=throughput_request_test.c
throughput_request_test_LDADD=testthroughput.la

throughput_report_test_SOURCES=throughput_report_test.c
throughput_report_test_LDADD=testthroughput.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../ -I../../../common/
