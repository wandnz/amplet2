#TESTS=sip_register.test sip_unresolved_target.test
#check_PROGRAMS=sip_register.test sip_unresolved_target.test
TESTS=sip_register.test
check_PROGRAMS=sip_register.test

check_LTLIBRARIES=testsip.la
testsip_la_SOURCES=../sip.c ../sip_common.c ../sip_server.c ../sip_client.c
nodist_testsip_la_SOURCES=../sip.pb-c.c
testsip_la_CFLAGS=-rdynamic -DUNIT_TEST -D_GNU_SOURCE -DAMP_EXTRA_DIRECTORY=\"\$(libdir)/\$(PACKAGE)/extra\"
testsip_la_LDFLAGS=-module -avoid-version -L../../../common/ -lamp -lprotobuf-c -lpj -lpjsua -lpjsip -lpjmedia

sip_register_test_SOURCES=sip_register_test.c
sip_register_test_LDADD=testsip.la

#sip_unresolved_target_test_SOURCES=sip_unresolved_target_test.c
#sip_unresolved_target_test_LDADD=testsip.la

AM_CFLAGS=-g -Wall -W -rdynamic -DUNIT_TEST
INCLUDES=-I../ -I../../../common/
