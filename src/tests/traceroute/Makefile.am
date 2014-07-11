EXTRA_DIST=*.h
SUBDIRS= . test

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-trace
amp_trace_SOURCES=traceroute.c ../testmain.c
amp_trace_LDADD=-L../../common/ -lamp -lwandevent

test_LTLIBRARIES=trace.la
trace_la_SOURCES=traceroute.c
trace_la_CFLAGS=-rdynamic
trace_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lwandevent

INCLUDES=-I../ -I../../common/
