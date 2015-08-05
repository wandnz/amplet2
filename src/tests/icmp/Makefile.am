EXTRA_DIST=*.h icmp.proto
SUBDIRS= . test
BUILT_SOURCES=icmp.pb-c.c
CLEANFILES=icmp.pb-c.c icmp.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-icmp
amp_icmp_SOURCES=icmp.c ../testmain.c
nodist_amp_icmp_SOURCES=icmp.pb-c.c
amp_icmp_LDADD=-L../../common/ -lamp -lprotobuf-c

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=icmp.c
nodist_icmp_la_SOURCES=icmp.pb-c.c
icmp_la_CFLAGS=-rdynamic
icmp_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

icmp.pb-c.c: Makefile
	protoc-c --c_out=. icmp.proto
	protoc --python_out=../python/ampsave.tests/ icmp.proto
