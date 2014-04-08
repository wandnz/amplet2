TESTS=send.test bind_address.test wait_for_data.test
check_PROGRAMS=send.test bind_address.test wait_for_data.test

send_test_SOURCES=send_test.c ../testlib.c
send_test_CFLAGS=-rdynamic -DUNIT_TEST
send_test_LDFLAGS=-module -avoid-version -L../ -lamp

bind_address_test_SOURCES=bind_address_test.c ../testlib.c
bind_address_test_CFLAGS=-rdynamic -DUNIT_TEST
bind_address_test_LDFLAGS=-module -avoid-version -L../ -lamp

wait_for_data_test_SOURCES=wait_for_data_test.c ../testlib.c
wait_for_data_test_CFLAGS=-rdynamic -DUNIT_TEST
wait_for_data_test_LDFLAGS=-module -avoid-version -L../ -lamp


AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../

