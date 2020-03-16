EXTRA_DIST=*.h dns.proto
SUBDIRS= . test
BUILT_SOURCES=dns.pb-c.c
CLEANFILES=dns.pb-c.c dns.pb-c.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-dns
amp_dns_SOURCES=../testmain.c
amp_dns_LDADD=dns.la -L../../common/ -lamp -lprotobuf-c -lunbound -levent
amp_dns_LDFLAGS=-Wl,--no-as-needed

test_LTLIBRARIES=dns.la
dns_la_SOURCES=dns.c
nodist_dns_la_SOURCES=dns.pb-c.c
dns_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -levent

INCLUDES=-I../ -I../../common/

dns.pb-c.c: dns.proto
	protoc-c --c_out=. dns.proto
	protoc --python_out=../python/ampsave/tests/ dns.proto
