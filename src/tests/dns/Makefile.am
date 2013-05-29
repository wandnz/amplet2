EXTRA_DIST=*.h

testdir=$(libdir)/$(PACKAGE)/tests

bin_PROGRAMS=amp-dns
amp_dns_SOURCES=dns.c ../testmain.c
amp_dns_LDADD=-L../../common/ -lamp

test_LTLIBRARIES=dns.la
dns_la_SOURCES=dns.c
dns_la_CFLAGS=-rdynamic
dns_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp

AM_CFLAGS=-g -Wall -W -rdynamic
INCLUDES=-I../ -I../../common/
