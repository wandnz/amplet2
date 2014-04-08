TESTS=nametable.test schedule_time.test
check_PROGRAMS=nametable.test schedule_time.test

nametable_test_SOURCES=nametable_test.c ../nametable.c
nametable_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST
nametable_test_LDFLAGS=-L../../common/ -lamp

schedule_time_test_SOURCES=schedule_time_test.c ../schedule.c ../watchdog.c ../nametable.c ../test.c
schedule_time_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST
schedule_time_test_LDFLAGS=-L../../common/ -lamp -lcurl -lwandevent

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/

