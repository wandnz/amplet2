TESTS=icmp_register.test icmp_checksum.test icmp_process_ipv4.test
check_PROGRAMS=icmp_register.test icmp_checksum.test icmp_process_ipv4.test

icmp_register_test_SOURCES=icmp_register_test.c ../icmp.c
nodist_icmp_register_test_SOURCES=../icmp.pb-c.c
icmp_register_test_CFLAGS=-rdynamic -DUNIT_TEST
icmp_register_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

icmp_checksum_test_SOURCES=icmp_checksum_test.c ../icmp.c
nodist_icmp_checksum_test_SOURCES=../icmp.pb-c.c
icmp_checksum_test_CFLAGS=-rdynamic -DUNIT_TEST
icmp_checksum_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c

icmp_process_ipv4_test_SOURCES=icmp_process_ipv4_test.c ../icmp.c
nodist_icmp_process_ipv4_test_SOURCES=../icmp.pb-c.c
icmp_process_ipv4_test_CFLAGS=-rdynamic -DUNIT_TEST
icmp_process_ipv4_test_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c


AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../ -I../../../common/

