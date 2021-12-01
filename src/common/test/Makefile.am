TESTS=send.test bind_address.test wait_for_data.test get_packet.test checksum.test compare_addresses.test
check_PROGRAMS=send.test bind_address.test wait_for_data.test get_packet.test checksum.test compare_addresses.test

send_test_SOURCES=send_test.c ../testlib.c
send_test_CFLAGS=-rdynamic -DUNIT_TEST
send_test_LDFLAGS=-L../ -lamp -lssl -lcrypto

bind_address_test_SOURCES=bind_address_test.c ../testlib.c
bind_address_test_CFLAGS=-rdynamic -DUNIT_TEST
bind_address_test_LDFLAGS=-L../ -lamp -lssl -lcrypto

wait_for_data_test_SOURCES=wait_for_data_test.c ../testlib.c
wait_for_data_test_CFLAGS=-rdynamic -DUNIT_TEST
wait_for_data_test_LDFLAGS=-L../ -lamp -lssl -lcrypto

get_packet_test_SOURCES=get_packet_test.c ../testlib.c
get_packet_test_CFLAGS=-rdynamic -DUNIT_TEST
get_packet_test_LDFLAGS=-L../ -lamp -lssl -lcrypto

checksum_test_SOURCES=checksum_test.c ../testlib.c
checksum_test_CFLAGS=-rdynamic -DUNIT_TEST
checksum_test_LDFLAGS=-L../ -lamp -lssl -lcrypto

compare_addresses_test_SOURCES=compare_addresses_test.c ../testlib.c
compare_addresses_test_CFLAGS=-rdynamic -DUNIT_TEST
compare_addresses_test_LDFLAGS=-L../ -lamp -lssl -lcrypto

AM_CFLAGS=-g -Wall -W -rdynamic
