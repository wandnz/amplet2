EXTRA_DIST=*.h ndt.proto
#SUBDIRS= . test
BUILT_SOURCES=ndt.pb-c.c
CLEANFILES=ndt.pb-c.c ndt.pb-c.h

if WANT_NDT_TEST

#SUBDIRS+=test
testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-ndt
amp_ndt_SOURCES=../testmain.c
amp_ndt_LDADD=ndt.la -L../../common/ -lamp -lprotobuf-c -lunbound -levent -lwebsockets -lcurl -ljansson

test_LTLIBRARIES=ndt.la
ndt_la_SOURCES=ndt.c locator.c
nodist_ndt_la_SOURCES=ndt.pb-c.c
ndt_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -levent -lwebsockets -lcurl -ljansson $(AM_LDFLAGS)

endif

ndt.pb-c.c: ndt.proto
	protoc-c --c_out=. ndt.proto
	protoc --python_out=../python/ampsave/tests/ ndt.proto
