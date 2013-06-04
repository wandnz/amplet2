EXTRA_DIST=*.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=throughput_client throughput_server
throughput_client_SOURCES=throughput_client.c throughput_common.c web10g.c ../testmain.c
throughput_client_LDADD=-L../../common/ -lamp

throughput_server_SOURCES=throughput_server.c throughput_common.c web10g.c ../testmain.c
throughput_server_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=throughput_client.la throughput_server.la
throughput_client_la_SOURCES=throughput_client.c throughput_common.c web10g.c
throughput_client_la_CFLAGS=-rdynamic
throughput_client_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

throughput_server_la_SOURCES=throughput_server.c throughput_common.c web10g.c
throughput_server_la_CFLAGS=-rdynamic
throughput_server_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp



AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/

if HAVE_ESTATS
throughput_client_LDADD += -lestats
throughput_server_LDADD += -lestats
throughput_client_la_LDFLAGS += -lestats
throughput_server_la_LDFLAGS += -lestats
AM_CPPFLAGS = -DHAVE_ESTATS
endif
