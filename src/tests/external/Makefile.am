EXTRA_DIST=*.h external.proto
SUBDIRS= . test
BUILT_SOURCES=external.pb-c.c
CLEANFILES=external.pb-c.c external.pb-c.h

if WANT_EXTERNAL_TEST

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-external
amp_external_SOURCES=../testmain.c
amp_external_LDADD=external.la -L../../common/ -lamp -lprotobuf-c -lunbound

test_LTLIBRARIES=external.la
external_la_SOURCES=external.c
nodist_external_la_SOURCES=external.pb-c.c
external_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

install-exec-local:
	mkdir -p $(DESTDIR)/$(libdir)/$(PACKAGE)/external

endif

external.pb-c.c: external.proto
	protoc-c --c_out=. external.proto
	protoc --python_out=../python/ampsave/tests/ external.proto
