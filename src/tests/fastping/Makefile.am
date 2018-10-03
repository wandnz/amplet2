EXTRA_DIST=fastping.proto

BUILT_SOURCES=fastping.pb-c.c
CLEANFILES=fastping.pb-c.c fastping.pb-c.h

if WANT_FASTPING_TEST

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-fastping
amp_fastping_SOURCES=../testmain.c
amp_fastping_LDADD=fastping.la -L../../common/ -lamp -lprotobuf-c -lunbound -lm
amp_fastping_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=fastping.la
fastping_la_SOURCES=stats.c fastping.c
nodist_fastping_la_SOURCES=fastping.pb-c.c
fastping_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/

endif

fastping.pb-c.c: Makefile
	protoc-c --c_out=. fastping.proto
	protoc --python_out=../python/ampsave/tests/ fastping.proto
