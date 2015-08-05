EXTRA_DIST=*.h tcpping.proto
BUILT_SOURCES=tcpping.pb-c.c
CLEANFILES=tcpping.pb-c.c tcpping.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-tcpping
amp_tcpping_SOURCES=pcapcapture.c tcpping.c ../testmain.c
nodist_amp_tcpping_SOURCES=tcpping.pb-c.c
amp_tcpping_LDADD=-L../../common/ -lamp -lwandevent -lpcap -lprotobuf-c

test_LTLIBRARIES=tcpping.la
tcpping_la_SOURCES=pcapcapture.c tcpping.c
nodist_tcpping_la_SOURCES=tcpping.pb-c.c
tcpping_la_CFLAGS=-rdynamic
tcpping_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lwandevent \
                -lpcap -lprotobuf-c

INCLUDES=-I../ -I../../common/

tcpping.pb-c.c: Makefile
	protoc-c --c_out=. tcpping.proto
	protoc --python_out=../python/ampsave.tests/ tcpping.proto
