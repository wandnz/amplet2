EXTRA_DIST=*.h throughput.proto
SUBDIRS= . test
BUILT_SOURCES=throughput.pb-c.c
CLEANFILES=throughput.pb-c.c throughput.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-throughput
amp_throughput_SOURCES=../testmain.c
amp_throughput_LDADD=throughput.la -L../../common/ -lamp -lprotobuf-c

test_LTLIBRARIES=throughput.la
throughput_la_SOURCES=throughput.c throughput_server.c throughput_common.c throughput_client.c web10g.c
nodist_throughput_la_SOURCES=throughput.pb-c.c
throughput_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

if HAVE_ESTATS
amp_throughput_LDADD += -lestats
throughput_la_LDFLAGS += -lestats
AM_CPPFLAGS = -DHAVE_ESTATS
endif

throughput.pb-c.c: Makefile
	protoc-c --c_out=. throughput.proto
	protoc --python_out=../python/ampsave.tests/ throughput.proto
