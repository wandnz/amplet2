TESTS=http_register.test http_split_url.test http_report.test
check_PROGRAMS=http_register.test http_split_url.test http_report.test

http_register_test_SOURCES=http_register_test.c ../http.c ../servers.c ../parsers.c ../output.c ../lexer.c
nodist_http_register_test_SOURCES=../http.pb-c.c
http_register_test_CFLAGS=-rdynamic -DUNIT_TEST
http_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lcurl -lprotobuf-c

http_split_url_test_SOURCES=http_split_url_test.c ../http.c ../servers.c ../parsers.c ../output.c ../lexer.c
nodist_http_split_url_test_SOURCES=../http.pb-c.c
http_split_url_test_CFLAGS=-rdynamic -DUNIT_TEST
http_split_url_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lcurl -lprotobuf-c

http_report_test_SOURCES=http_report_test.c ../http.c ../servers.c ../parsers.c ../output.c ../lexer.c
nodist_http_report_test_SOURCES=../http.pb-c.c
http_report_test_CFLAGS=-rdynamic -DUNIT_TEST
http_report_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lcurl -lprotobuf-c

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

