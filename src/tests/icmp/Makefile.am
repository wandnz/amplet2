EXTRA_DIST=*.h icmp.proto
SUBDIRS= . test
BUILT_SOURCES=icmp.pb-c.c
CLEANFILES=icmp.pb-c.c icmp.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-icmp
amp_icmp_SOURCES=../testmain.c
amp_icmp_LDADD=icmp.la -L../../common/ -lamp -lprotobuf-c -lunbound -levent
amp_icmp_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=icmp.c
nodist_icmp_la_SOURCES=icmp.pb-c.c
icmp_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -levent

INCLUDES=-I../ -I../../common/

install-exec-hook:
	setcap 'CAP_NET_RAW=ep' $(DESTDIR)/$(bindir)/amp-icmp

icmp.pb-c.c: icmp.proto
	protoc-c --c_out=. icmp.proto
	protoc --python_out=../python/ampsave/tests/ icmp.proto
