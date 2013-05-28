EXTRA_DIST=*.h

testdir=$(prefix)/tests

bin_PROGRAMS=icmp
icmp_SOURCES=icmp.c ../testmain.c
icmp_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=icmp.c
icmp_la_CFLAGS=-rdynamic
icmp_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
