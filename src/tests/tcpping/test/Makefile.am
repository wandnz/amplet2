TESTS=tcpping_register.test tcpping_report.test
check_PROGRAMS=tcpping_register.test tcpping_report.test

tcpping_register_test_SOURCES=tcpping_register_test.c ../tcpping.c ../pcapcapture.c
nodist_tcpping_register_test_SOURCES=../tcpping.pb-c.c
tcpping_register_test_CFLAGS=-rdynamic -DUNIT_TEST
tcpping_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lwandevent -lpcap -lprotobuf-c

tcpping_report_test_SOURCES=tcpping_report_test.c ../tcpping.c ../pcapcapture.c
nodist_tcpping_report_test_SOURCES=../tcpping.pb-c.c
tcpping_report_test_CFLAGS=-rdynamic -DUNIT_TEST
tcpping_report_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lwandevent -lpcap -lprotobuf-c

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

