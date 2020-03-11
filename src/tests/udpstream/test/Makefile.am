TESTS=udpstream_register.test udpstream_hello.test udpstream_ready.test udpstream_request.test udpstream_unresolved_target.test
check_PROGRAMS=udpstream_register.test udpstream_hello.test udpstream_ready.test udpstream_request.test udpstream_unresolved_target.test

check_LTLIBRARIES=testudpstream.la
testudpstream_la_SOURCES=../udpstream.c ../udpstream_server.c ../udpstream_client.c ../udpstream_common.c
nodist_testudpstream_la_SOURCES=../udpstream.pb-c.c
testudpstream_la_CFLAGS=-rdynamic -DUNIT_TEST
testudpstream_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c -lm

udpstream_register_test_SOURCES=udpstream_register_test.c
udpstream_register_test_LDADD=testudpstream.la

udpstream_hello_test_SOURCES=udpstream_hello_test.c
udpstream_hello_test_LDADD=testudpstream.la

udpstream_ready_test_SOURCES=udpstream_ready_test.c
udpstream_ready_test_LDADD=testudpstream.la

udpstream_request_test_SOURCES=udpstream_request_test.c
udpstream_request_test_LDADD=testudpstream.la

udpstream_unresolved_target_test_SOURCES=udpstream_unresolved_target_test.c
udpstream_unresolved_target_test_LDADD=testudpstream.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../ -I../../../common/
