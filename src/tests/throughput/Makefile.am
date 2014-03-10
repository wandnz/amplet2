EXTRA_DIST=*.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=throughput
throughput_SOURCES=throughput_server.c throughput_common.c throughput_client.c web10g.c ../testmain.c
throughput_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=throughput.la
throughput_la_SOURCES=throughput_server.c throughput_common.c throughput_client.c web10g.c
throughput_la_CFLAGS=-rdynamic
throughput_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp



INCLUDES=-I../ -I../../common/

if HAVE_ESTATS
throughput_LDADD += -lestats
throughput_la_LDFLAGS += -lestats
AM_CPPFLAGS = -DHAVE_ESTATS
endif
