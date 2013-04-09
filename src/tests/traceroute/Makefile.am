EXTRA_DIST=*.h

testdir=$(prefix)/tests

bin_PROGRAMS=trace
trace_SOURCES=traceroute.c ../testmain.c
trace_LDFLAGS=-L../ -lmeasured
trace_LDADD=-L../ -lmeasured

test_LTLIBRARIES=trace.la
trace_la_SOURCES=traceroute.c
trace_la_CFLAGS=-rdynamic
trace_la_LDFLAGS=-module -avoid-version -L../ -lmeasured

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/ -I../
