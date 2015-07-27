EXTRA_DIST=*.h dns.proto
SUBDIRS= . test

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-dns
amp_dns_SOURCES=dns.c ../testmain.c dns.pb-c.c
amp_dns_LDADD=-L../../common/ -lamp -lprotobuf-c

test_LTLIBRARIES=dns.la
dns_la_SOURCES=dns.c dns.pb-c.c
dns_la_CFLAGS=-rdynamic
dns_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/
