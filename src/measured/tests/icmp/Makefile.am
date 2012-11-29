testdir=$(prefix)/tests/

bin_PROGRAMS=icmp
icmp_SOURCES=icmp.c ../testmain.c
icmp_LDFLAGS=-L../../.libs/ -lmeasured
icmp_LDADD=-L../../.libs/ -lmeasured

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=icmp.c
icmp_la_CFLAGS=-rdynamic
icmp_la_LDFLAGS=-module -avoid-version -L../../.libs/ -lmeasured

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../../
