TESTS=icmp_register.test icmp_process_ipv4.test icmp_report.test icmp_unresolved_target.test
check_PROGRAMS=icmp_register.test icmp_process_ipv4.test icmp_report.test icmp_unresolved_target.test

check_LTLIBRARIES=testicmp.la
testicmp_la_SOURCES=../icmp.c
nodist_testicmp_la_SOURCES=../icmp.pb-c.c
testicmp_la_CFLAGS=-rdynamic -DUNIT_TEST
testicmp_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c -levent

icmp_register_test_SOURCES=icmp_register_test.c
icmp_register_test_LDADD=testicmp.la

icmp_process_ipv4_test_SOURCES=icmp_process_ipv4_test.c
icmp_process_ipv4_test_LDADD=testicmp.la

icmp_report_test_SOURCES=icmp_report_test.c
icmp_report_test_LDADD=testicmp.la

icmp_unresolved_target_test_SOURCES=icmp_unresolved_target_test.c
icmp_unresolved_target_test_LDADD=testicmp.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
AM_CPPFLAGS+=-I../
