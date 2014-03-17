TESTS=dns_register.test dns_encode.test dns_decode.test
check_PROGRAMS=dns_register.test dns_encode.test dns_decode.test

dns_register_test_SOURCES=dns_register_test.c ../dns.c
dns_register_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp

dns_encode_test_SOURCES=dns_encode_test.c ../dns.c
dns_encode_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_encode_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp

dns_decode_test_SOURCES=dns_decode_test.c ../dns.c
dns_decode_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_decode_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp


AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

