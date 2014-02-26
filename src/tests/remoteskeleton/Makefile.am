testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-remoteskeleton
amp_remoteskeleton_SOURCES=remoteskeleton.c ../testmain.c
amp_remoteskeleton_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=remoteskeleton.la
remoteskeleton_la_SOURCES=remoteskeleton.c
remoteskeleton_la_CFLAGS=-rdynamic
remoteskeleton_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

INCLUDES=-I../ -I../../common/
