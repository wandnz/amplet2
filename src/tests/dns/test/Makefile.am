TESTS=dns_register.test dns_encode.test dns_decode.test dns_report.test
check_PROGRAMS=dns_register.test dns_encode.test dns_decode.test dns_report.test

check_LTLIBRARIES=testdns.la
testdns_la_SOURCES=../dns.c
nodist_testdns_la_SOURCES=../dns.pb-c.c
testdns_la_CFLAGS=-rdynamic -DUNIT_TEST
testdns_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c -lwandevent

dns_register_test_SOURCES=dns_register_test.c
dns_register_test_LDADD=testdns.la

dns_encode_test_SOURCES=dns_encode_test.c
dns_encode_test_LDADD=testdns.la

dns_decode_test_SOURCES=dns_decode_test.c
dns_decode_test_LDADD=testdns.la

dns_report_test_SOURCES=dns_report_test.c
dns_report_test_LDADD=testdns.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../ -I../../../common/
