EXTRA_DIST=*.h
SUBDIRS= . test

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-icmp
amp_icmp_SOURCES=icmp.c ../testmain.c
amp_icmp_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=icmp.la
icmp_la_SOURCES=icmp.c
icmp_la_CFLAGS=-rdynamic
icmp_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
