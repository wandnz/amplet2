EXTRA_DIST=*.h
SUBDIRS= . test

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-throughput
amp_throughput_SOURCES=throughput.c throughput_server.c throughput_common.c throughput_client.c web10g.c ../testmain.c
amp_throughput_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=throughput.la
throughput_la_SOURCES=throughput.c throughput_server.c throughput_common.c throughput_client.c web10g.c
throughput_la_CFLAGS=-rdynamic
throughput_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp



INCLUDES=-I../ -I../../common/

if HAVE_ESTATS
amp_throughput_LDADD += -lestats
throughput_la_LDFLAGS += -lestats
AM_CPPFLAGS = -DHAVE_ESTATS
endif
