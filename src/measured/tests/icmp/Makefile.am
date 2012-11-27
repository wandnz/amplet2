#EXTRA_DIST=*.h

testdir=$(prefix)/tests/

bin_PROGRAMS=icmp
icmp_SOURCES=icmp.c
icmp_LDFLAGS=-L../../.libs/ -lmeasured
icmp_LDADD=-L../../.libs/ -lmeasured

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=register_icmp.c
icmp_la_CFLAGS=-rdynamic
icmp_la_LDFLAGS=-module -avoid-version

AM_CFLAGS=-g -Wall -W
INCLUDES=-I../../
