TESTS=dns_register.test dns_encode.test dns_decode.test dns_report.test
check_PROGRAMS=dns_register.test dns_encode.test dns_decode.test dns_report.test

dns_register_test_SOURCES=dns_register_test.c ../dns.c
nodist_dns_register_test_SOURCES=../dns.pb-c.c
dns_register_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

dns_encode_test_SOURCES=dns_encode_test.c ../dns.c
nodist_dns_encode_test_SOURCES=../dns.pb-c.c
dns_encode_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_encode_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

dns_decode_test_SOURCES=dns_decode_test.c ../dns.c
nodist_dns_decode_test_SOURCES=../dns.pb-c.c
dns_decode_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_decode_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

dns_report_test_SOURCES=dns_report_test.c ../dns.c
nodist_dns_report_test_SOURCES=../dns.pb-c.c
dns_report_test_CFLAGS=-rdynamic -DUNIT_TEST
dns_report_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

