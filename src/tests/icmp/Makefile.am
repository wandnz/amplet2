EXTRA_DIST=*.h icmp.proto
SUBDIRS= . test

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-icmp
amp_icmp_SOURCES=icmp.c ../testmain.c icmp.pb-c.c
amp_icmp_LDADD=-L../../common/ -lamp -lprotobuf-c

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=icmp.c icmp.pb-c.c
icmp_la_CFLAGS=-rdynamic
icmp_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c

INCLUDES=-I../ -I../../common/
