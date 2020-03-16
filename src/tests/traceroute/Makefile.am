EXTRA_DIST=*.h traceroute.proto
SUBDIRS= . test
BUILT_SOURCES=traceroute.pb-c.c
CLEANFILES=traceroute.pb-c.c traceroute.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-trace
amp_trace_SOURCES=../testmain.c
amp_trace_LDADD=trace.la -L../../common/ -lamp -levent -lpthread -lunbound -lprotobuf-c -lunbound
amp_trace_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=trace.la
trace_la_SOURCES=traceroute.c as.c
nodist_trace_la_SOURCES=traceroute.pb-c.c
trace_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -levent -lpthread -lunbound -lprotobuf-c

INCLUDES=-I../ -I../../common/

install-exec-local:
	setcap 'CAP_NET_RAW=ep' $(DESTDIR)/$(bindir)/amp-trace

traceroute.pb-c.c: traceroute.proto
	protoc-c --c_out=. traceroute.proto
	protoc --python_out=../python/ampsave/tests/ traceroute.proto
