TESTS=http_register.test http_split_url.test http_report.test http_unresolved_target.test
check_PROGRAMS=http_register.test http_split_url.test http_report.test http_unresolved_target.test

check_LTLIBRARIES=testhttp.la
testhttp_la_SOURCES=../http.c ../servers.c ../parsers.c ../output.c ../lexer.c
nodist_testhttp_la_SOURCES=../http.pb-c.c
testhttp_la_CFLAGS=-rdynamic -DUNIT_TEST -D_GNU_SOURCE
testhttp_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lcurl -lprotobuf-c

http_register_test_SOURCES=http_register_test.c
http_register_test_LDADD=testhttp.la

http_split_url_test_SOURCES=http_split_url_test.c
http_split_url_test_LDADD=testhttp.la

http_report_test_SOURCES=http_report_test.c
http_report_test_LDADD=testhttp.la

http_unresolved_target_test_SOURCES=http_unresolved_target_test.c
http_unresolved_target_test_LDADD=testhttp.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../ -I../../../common/
