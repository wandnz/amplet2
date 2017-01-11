EXTRA_DIST=remoteskeleton.proto

BUILT_SOURCES=remoteskeleton.pb-c.c
CLEANFILES=remoteskeleton.pb-c.c remoteskeleton.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-remoteskeleton
amp_remoteskeleton_SOURCES=../testmain.c
amp_remoteskeleton_LDADD=remoteskeleton.la -L../../common/ -lamp -lprotobuf-c -lunbound
amp_remoteskeleton_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=remoteskeleton.la
remoteskeleton_la_SOURCES=remoteskeleton.c
nodist_remoteskeleton_la_SOURCES=remoteskeleton.pb-c.c
remoteskeleton_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

remoteskeleton.pb-c.c: Makefile
	protoc-c --c_out=. remoteskeleton.proto
	protoc --python_out=../python/ampsave/tests/ remoteskeleton.proto
