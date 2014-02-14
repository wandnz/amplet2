TESTS=nametable.test
check_PROGRAMS=nametable.test

nametable_test_SOURCES=nametable_test.c ../nametable.c
nametable_test_CFLAGS=-DAMP_CONFIG_DIR=\"$(sysconfdir)/$(PACKAGE)\" -DAMP_TEST_DIRECTORY=\"$(libdir)/$(PACKAGE)/tests\" -rdynamic -DUNIT_TEST
nametable_test_LDFLAGS=-L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/

