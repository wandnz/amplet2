TESTS=nametable.test schedule_time.test schedule_parseparam.test acl.test
check_PROGRAMS=nametable.test schedule_time.test schedule_parseparam.test acl.test

nametable_test_SOURCES=nametable_test.c ../nametable.c
nametable_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST
nametable_test_LDFLAGS=-L../../common/ -lamp -lunbound

schedule_time_test_SOURCES=schedule_time_test.c ../schedule.c ../watchdog.c ../nametable.c ../run.c ../messaging.c ../libevent_foreach.c
schedule_time_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST -D_GNU_SOURCE
schedule_time_test_LDFLAGS=-L../../common/ -lrabbitmq -lamp -lcurl -levent -lyaml -lrt -lcrypto -lunbound

schedule_parseparam_test_SOURCES=schedule_parseparam_test.c ../schedule.c ../watchdog.c ../nametable.c ../run.c ../messaging.c ../libevent_foreach.c
schedule_parseparam_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST -D_GNU_SOURCE
schedule_parseparam_test_LDFLAGS=-L../../common/ -lrabbitmq -lamp -lcurl -levent -lyaml -lrt -lcrypto -lunbound

acl_test_SOURCES=acl_test.c ../acl.c
acl_test_LDFLAGS=-L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
AM_CPPFLAGS+=-I../
