TESTS=throughput_register.test throughput_hello.test throughput_ready.test throughput_request.test
check_PROGRAMS=throughput_register.test throughput_hello.test throughput_ready.test throughput_request.test

throughput_register_test_SOURCES=throughput_register_test.c ../throughput.c ../throughput_server.c ../throughput_client.c ../throughput_common.c ../web10g.c
throughput_register_test_CFLAGS=-rdynamic -DUNIT_TEST
throughput_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp

throughput_hello_test_SOURCES=throughput_hello_test.c ../throughput_common.c
throughput_hello_test_CFLAGS=-rdynamic -DUNIT_TEST
throughput_hello_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp

throughput_ready_test_SOURCES=throughput_ready_test.c ../throughput_common.c
throughput_ready_test_CFLAGS=-rdynamic -DUNIT_TEST
throughput_ready_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp

throughput_request_test_SOURCES=throughput_request_test.c ../throughput_common.c
throughput_request_test_CFLAGS=-rdynamic -DUNIT_TEST
throughput_request_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp


AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

