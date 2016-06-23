TESTS=nametable.test schedule_time.test acl.test # XXX required?
check_PROGRAMS=nametable.test schedule_time.test acl.test

nametable_test_SOURCES=nametable_test.c ../nametable.c
nametable_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST
nametable_test_LDFLAGS=-L../../common/ -lamp

schedule_time_test_SOURCES=schedule_time_test.c ../schedule.c ../watchdog.c ../nametable.c ../test.c
schedule_time_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST -D_GNU_SOURCE
schedule_time_test_LDFLAGS=-L../../common/ -lamp -lcurl -lwandevent -lyaml -lrt -lcrypto

acl_test_SOURCES=acl_test.c ../acl.c
acl_test_LDFLAGS=-L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
